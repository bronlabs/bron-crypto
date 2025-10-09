package sign_softspoken

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
)

func (c *Cosigner[P, B, S]) Round1() (r1b *Round1Broadcast, r1u network.RoundMessages[*Round1P2P], err error) {
	if c.state.round != 1 {
		return nil, nil, errs.NewFailed("invalid round")
	}

	var ck [hash_comm.KeySize]byte
	ckBytes, err := c.tape.ExtractBytes(ckLabel, uint(len(ck)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to extract commitment key")
	}
	copy(ck[:], ckBytes)
	c.state.ck, err = hash_comm.NewScheme(ck)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create commitment scheme")
	}

	c.state.r, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample r")
	}
	c.state.bigR = make(map[sharing.ID]P)
	c.state.bigR[c.shard.Share().ID()] = c.suite.Curve().ScalarBaseMul(c.state.r)
	c.state.bigRCommitment = make(map[sharing.ID]hash_comm.Commitment)
	c.state.bigRCommitment[c.shard.Share().ID()], c.state.bigRWitness, err = c.state.ck.Committer().Commit(c.state.bigR[c.shard.Share().ID()].ToCompressed(), c.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit to r")
	}

	c.state.phi, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample phi")
	}

	c.state.chi = make(map[sharing.ID]S)
	bOut := &Round1Broadcast{
		BigRCommitment: c.state.bigRCommitment[c.shard.Share().ID()],
	}
	uOut := hashmap.NewComparable[sharing.ID, *Round1P2P]()
	for id, message := range outgoingP2PMessages(c, uOut) {
		message.MulR1, c.state.chi[id], err = c.state.bobMul[id].Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run Bob mul round1")
		}
	}

	c.state.round++
	return bOut, uOut.Freeze(), nil
}

func (c *Cosigner[P, B, S]) Round2(r1b network.RoundMessages[*Round1Broadcast], r1u network.RoundMessages[*Round1P2P]) (r2b *Round2Broadcast[P, B, S], r2u network.RoundMessages[*Round2P2P[P, B, S]], err error) {
	incomingMessages, err := validateIncomingMessages(c, 2, r1b, r1u)
	if err != nil {
		return nil, nil, errs.NewFailed("invalid input or round mismatch")
	}

	mulR1 := make(map[sharing.ID]*rvole_softspoken.Round1P2P)
	for id, message := range incomingMessages {
		c.state.bigRCommitment[id] = message.broadcast.BigRCommitment
		mulR1[id] = message.p2p.MulR1
	}

	c.state.zeroSampler, err = przs.NewSampler(c.shard.Share().ID(), c.quorum, c.zeroSeeds, c.suite.ScalarField())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
	}
	zeta, err := c.state.zeroSampler.Sample()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
	}

	quorum, err := sharing.NewMinimalQualifiedAccessStructure(c.quorum)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create minimal qualified access structure")
	}
	sk, err := c.shard.Share().ToAdditive(*quorum)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "to additive share failed")
	}
	c.state.sk = sk.Value().Add(zeta)
	c.state.pk = make(map[sharing.ID]P)
	c.state.pk[c.shard.Share().ID()] = c.suite.Curve().ScalarBaseMul(c.state.sk)
	c.state.c = make(map[sharing.ID][]S)

	bOut := &Round2Broadcast[P, B, S]{
		BigR:        c.state.bigR[c.shard.Share().ID()],
		BigRWitness: c.state.bigRWitness,
		Pk:          c.state.pk[c.shard.Share().ID()],
	}
	uOut := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id, message := range outgoingP2PMessages(c, uOut) {
		message.MulR2, c.state.c[id], err = c.state.aliceMul[id].Round2(mulR1[id], []S{c.state.r, c.state.sk})
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run alice mul round2")
		}
		message.GammaU = c.suite.Curve().ScalarBaseMul(c.state.c[id][0])
		message.GammaV = c.suite.Curve().ScalarBaseMul(c.state.c[id][1])
		message.Psi = c.state.phi.Sub(c.state.chi[id])
	}

	c.state.round++
	return bOut, uOut.Freeze(), nil
}

func (c *Cosigner[P, B, S]) Round3(r2b network.RoundMessages[*Round2Broadcast[P, B, S]], r2u network.RoundMessages[*Round2P2P[P, B, S]], message []byte) (partialSignature *dkls23.PartialSignature[P, B, S], err error) {
	incomingMessages, err := validateIncomingMessages(c, 3, r2b, r2u)
	if err != nil {
		return nil, errs.NewFailed("invalid input or round mismatch")
	}

	psi := c.suite.ScalarField().Zero()
	cudu := c.suite.ScalarField().Zero()
	cvdv := c.suite.ScalarField().Zero()
	for id, message := range incomingMessages {
		if err := c.state.ck.Verifier().Verify(c.state.bigRCommitment[id], message.broadcast.BigR.ToCompressed(), message.broadcast.BigRWitness); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, id, "invalid commitment")
		}
		c.state.bigR[id] = message.broadcast.BigR

		d, err := c.state.bobMul[id].Round3(message.p2p.MulR2)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run Bob mul round3")
		}
		if !c.state.bigR[id].ScalarMul(c.state.chi[id]).Sub(message.p2p.GammaU).Equal(c.suite.Curve().ScalarBaseMul(d[0])) {
			return nil, errs.NewFailed("consistency check failed")
		}
		if !message.broadcast.Pk.ScalarMul(c.state.chi[id]).Sub(message.p2p.GammaV).Equal(c.suite.Curve().ScalarBaseMul(d[1])) {
			return nil, errs.NewFailed("consistency check failed")
		}
		c.state.pk[id] = message.broadcast.Pk

		psi = psi.Add(message.p2p.Psi)
		cudu = cudu.Add(c.state.c[id][0].Add(d[0]))
		cvdv = cvdv.Add(c.state.c[id][1].Add(d[1]))
	}

	bigR := sliceutils.Fold(func(x, y P) P { return x.Add(y) }, c.suite.Curve().OpIdentity(), slices.Collect(maps.Values(c.state.bigR))...)
	pk := sliceutils.Fold(func(x, y P) P { return x.Add(y) }, c.suite.Curve().OpIdentity(), slices.Collect(maps.Values(c.state.pk))...)
	if !pk.Equal(c.shard.PublicKey().Value()) {
		return nil, errs.NewFailed("consistency check failed")
	}

	u := c.state.r.Mul(c.state.phi.Add(psi)).Add(cudu)
	v := c.state.sk.Mul(c.state.phi.Add(psi)).Add(cvdv)
	digest, err := hashing.Hash(c.suite.HashFunc(), message)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash message")
	}
	m, err := ecdsa.DigestToScalar(c.suite.ScalarField(), digest)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute message scalar")
	}
	rxi, err := bigR.AffineX()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert to affine x")
	}
	rx, err := c.suite.ScalarField().FromWideBytes(rxi.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert to scalar")
	}
	w := m.Mul(c.state.phi).Add(rx.Mul(v))

	partialSignature, err = dkls23.NewPartialSignature(c.state.bigR[c.shard.Share().ID()], u, w)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create partial signature")
	}
	return partialSignature, nil
}
