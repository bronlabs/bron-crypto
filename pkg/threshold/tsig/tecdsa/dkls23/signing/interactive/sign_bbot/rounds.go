package sign_bbot

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	rvole_bbot "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/bbot"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
	"github.com/bronlabs/errs-go/errs"
)

// Round1 executes protocol round 1.
func (c *Cosigner[P, B, S]) Round1() (r1bOut *Round1Broadcast, r1uOut network.RoundMessages[*Round1P2P[P, B, S]], err error) {
	if c.state.round != 1 {
		return nil, nil, ErrFailed.WithMessage("invalid round")
	}

	var ck [hash_comm.KeySize]byte
	ckBytes, err := c.tape.ExtractBytes(ckLabel, uint(len(ck)))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to extract commitment key")
	}
	copy(ck[:], ckBytes)
	c.state.ck, err = hash_comm.NewScheme(ck)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create commitment scheme")
	}

	c.state.r, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample r")
	}
	c.state.bigR = make(map[sharing.ID]P)
	c.state.bigR[c.shard.Share().ID()] = c.suite.Curve().ScalarBaseMul(c.state.r)
	c.state.bigRCommitment = make(map[sharing.ID]hash_comm.Commitment)
	committer, err := c.state.ck.Committer()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create committer")
	}
	c.state.bigRCommitment[c.shard.Share().ID()], c.state.bigRWitness, err = committer.Commit(c.state.bigR[c.shard.Share().ID()].ToCompressed(), c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot commit to r")
	}

	c.state.phi, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample phi")
	}

	zeroR1, err := c.state.zeroSetup.Round1()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot round 1 of zero setup")
	}

	bOut := &Round1Broadcast{
		ZeroSetupR1:    zeroR1,
		BigRCommitment: c.state.bigRCommitment[c.shard.Share().ID()],
	}
	uOut := hashmap.NewComparable[sharing.ID, *Round1P2P[P, B, S]]()
	for id, message := range outgoingP2PMessages(c, uOut) {
		message.MulR1, err = c.state.aliceMul[id].Round1()
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run Alice mul round1")
		}
	}

	c.state.round++
	return bOut, uOut.Freeze(), nil
}

// Round2 executes protocol round 2.
func (c *Cosigner[P, B, S]) Round2(r1bOut network.RoundMessages[*Round1Broadcast], r1uOut network.RoundMessages[*Round1P2P[P, B, S]]) (r2bOut *Round2Broadcast[P, B, S], r2uOut network.RoundMessages[*Round2P2P[P, B, S]], err error) {
	incomingMessages, err := validateIncomingMessages(c, 2, r1bOut, r1uOut)
	if err != nil {
		return nil, nil, ErrFailed.WithMessage("invalid input or round mismatch")
	}

	zeroR1 := hashmap.NewComparable[sharing.ID, *przsSetup.Round1Broadcast]()
	mulR1 := make(map[sharing.ID]*rvole_bbot.Round1P2P[P, S])
	for id, message := range incomingMessages {
		c.state.bigRCommitment[id] = message.broadcast.BigRCommitment
		zeroR1.Put(id, message.broadcast.ZeroSetupR1)
		mulR1[id] = message.p2p.MulR1
	}

	zeroR2, err := c.state.zeroSetup.Round2(zeroR1.Freeze())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run zero setup round2")
	}

	c.state.chi = make(map[sharing.ID]S)
	bOut := &Round2Broadcast[P, B, S]{
		BigR:        c.state.bigR[c.shard.Share().ID()],
		BigRWitness: c.state.bigRWitness,
	}
	uOut := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id, message := range outgoingP2PMessages(c, uOut) {
		message.MulR2, c.state.chi[id], err = c.state.bobMul[id].Round2(mulR1[id])
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run bob mul round2")
		}
		message.ZeroSetupR2, _ = zeroR2.Get(id)
	}

	c.state.round++
	return bOut, uOut.Freeze(), nil
}

// Round3 executes protocol round 3.
func (c *Cosigner[P, B, S]) Round3(r2bOut network.RoundMessages[*Round2Broadcast[P, B, S]], r2uOut network.RoundMessages[*Round2P2P[P, B, S]]) (r3bOut *Round3Broadcast[P, B, S], r3uOut network.RoundMessages[*Round3P2P[P, B, S]], err error) {
	incomingMessages, err := validateIncomingMessages(c, 3, r2bOut, r2uOut)
	if err != nil {
		return nil, nil, ErrFailed.WithMessage("invalid input or round mismatch")
	}

	zeroR2 := hashmap.NewComparable[sharing.ID, *przsSetup.Round2P2P]()
	mulR2 := make(map[sharing.ID]*rvole_bbot.Round2P2P[P, S])
	verifier, err := c.state.ck.Verifier()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create verifier")
	}
	for id, message := range incomingMessages {
		if err := verifier.Verify(c.state.bigRCommitment[id], message.broadcast.BigR.ToCompressed(), message.broadcast.BigRWitness); err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid commitment")
		}
		c.state.bigR[id] = message.broadcast.BigR
		zeroR2.Put(id, message.p2p.ZeroSetupR2)
		mulR2[id] = message.p2p.MulR2
	}

	zeroSeeds, err := c.state.zeroSetup.Round3(zeroR2.Freeze())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run zero setup round3")
	}
	c.state.zeroSampler, err = przs.NewSampler(c.shard.Share().ID(), c.quorum, zeroSeeds, c.suite.ScalarField())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run zero setup round3")
	}
	zeta, err := c.state.zeroSampler.Sample()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run zero setup round3")
	}

	quorum2, err := sharing.NewMinimalQualifiedAccessStructure(c.quorum)
	if err != nil {
		panic(err)
	}

	sk, err := c.shard.Share().ToAdditive(quorum2)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("to additive share failed")
	}

	c.state.sk = sk.Value().Add(zeta)
	c.state.pk = make(map[sharing.ID]P)
	c.state.pk[c.shard.Share().ID()] = c.suite.Curve().ScalarBaseMul(c.state.sk)
	c.state.c = make(map[sharing.ID][]S)

	bOut := &Round3Broadcast[P, B, S]{Pk: c.state.pk[c.shard.Share().ID()]}
	uOut := hashmap.NewComparable[sharing.ID, *Round3P2P[P, B, S]]()
	for id, message := range outgoingP2PMessages(c, uOut) {
		message.MulR3, c.state.c[id], err = c.state.aliceMul[id].Round3(mulR2[id], []S{c.state.r, c.state.sk})
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run alice mul round3")
		}
		message.GammaU = c.suite.Curve().ScalarBaseMul(c.state.c[id][0])
		message.GammaV = c.suite.Curve().ScalarBaseMul(c.state.c[id][1])
		message.Psi = c.state.phi.Sub(c.state.chi[id])
	}

	c.state.round++
	return bOut, uOut.Freeze(), nil
}

// Round4 executes protocol round 4.
func (c *Cosigner[P, B, S]) Round4(r3bOut network.RoundMessages[*Round3Broadcast[P, B, S]], r3uOut network.RoundMessages[*Round3P2P[P, B, S]], message []byte) (partialSignature *dkls23.PartialSignature[P, B, S], err error) {
	incomingMessages, err := validateIncomingMessages(c, 4, r3bOut, r3uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid input or round mismatch")
	}

	psi := c.suite.ScalarField().Zero()
	cudu := c.suite.ScalarField().Zero()
	cvdv := c.suite.ScalarField().Zero()
	for id, message := range incomingMessages {
		d, err := c.state.bobMul[id].Round4(message.p2p.MulR3)
		if err != nil {
			if errs.Is(err, base.ErrAbort) {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot run Bob mul round4")
			}
			return nil, errs.Wrap(err).WithMessage("cannot run Bob mul round4")
		}
		c.state.pk[id] = message.broadcast.Pk

		if !c.state.bigR[id].ScalarMul(c.state.chi[id]).Sub(message.p2p.GammaU).Equal(c.suite.Curve().ScalarBaseMul(d[0])) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("consistency check failed")
		}
		if !message.broadcast.Pk.ScalarMul(c.state.chi[id]).Sub(message.p2p.GammaV).Equal(c.suite.Curve().ScalarBaseMul(d[1])) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("consistency check failed")
		}

		psi = psi.Add(message.p2p.Psi)
		cudu = cudu.Add(c.state.c[id][0].Add(d[0]))
		cvdv = cvdv.Add(c.state.c[id][1].Add(d[1]))
	}

	bigR := sliceutils.Fold(func(x, y P) P { return x.Add(y) }, c.suite.Curve().OpIdentity(), slices.Collect(maps.Values(c.state.bigR))...)
	pk := sliceutils.Fold(func(x, y P) P { return x.Add(y) }, c.suite.Curve().OpIdentity(), slices.Collect(maps.Values(c.state.pk))...)
	if !pk.Equal(c.shard.PublicKey().Value()) {
		return nil, base.ErrAbort.WithMessage("consistency check failed")
	}

	u := c.state.r.Mul(c.state.phi.Add(psi)).Add(cudu)
	v := c.state.sk.Mul(c.state.phi.Add(psi)).Add(cvdv)
	digest, err := hashing.Hash(c.suite.HashFunc(), message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot hash message")
	}
	m, err := ecdsa.DigestToScalar(c.suite.ScalarField(), digest)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert digest to scalar")
	}
	rxi, err := bigR.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert to affine x")
	}
	rx, err := c.suite.ScalarField().FromWideBytes(rxi.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert to scalar")
	}
	w := m.Mul(c.state.phi).Add(rx.Mul(v))

	partialSignature, err = dkls23.NewPartialSignature(bigR, u, w)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create partial signature")
	}
	return partialSignature, nil
}
