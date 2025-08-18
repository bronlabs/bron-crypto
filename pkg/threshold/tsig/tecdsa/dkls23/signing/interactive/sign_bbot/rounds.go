package sign_bbot

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/mul_bbot"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
)

func (c *Cosigner[P, B, S]) Round1() (r1bOut *Round1Broadcast, r1uOut network.RoundMessages[*Round1P2P[P, B, S]], err error) {
	if c.State.Round != 1 {
		return nil, nil, errs.NewFailed("invalid round")
	}

	var ck [32]byte
	ckBytes, err := c.Tape.ExtractBytes(ckLabel, uint(len(ck)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to extract commitment key")
	}
	copy(ck[:], ckBytes)
	c.State.Ck, err = hash_comm.NewScheme(ck)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create commitment scheme")
	}

	c.State.R, err = c.Suite.ScalarField().Random(c.Prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample r")
	}
	c.State.BigR = make(map[sharing.ID]P)
	c.State.BigR[c.MySharingId] = c.Suite.Curve().ScalarBaseMul(c.State.R)
	c.State.BigRCommitment = make(map[sharing.ID]hash_comm.Commitment)
	c.State.BigRCommitment[c.MySharingId], c.State.BigRWitness, err = c.State.Ck.Committer().Commit(c.State.BigR[c.MySharingId].ToCompressed(), c.Prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit to r")
	}

	c.State.Phi, err = c.Suite.ScalarField().Random(c.Prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample phi")
	}

	zeroR1, err := c.State.ZeroSetup.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot round 1 of zero setup")
	}

	bOut := &Round1Broadcast{
		ZeroSetupR1:    zeroR1,
		BigRCommitment: c.State.BigRCommitment[c.MySharingId],
	}
	uOut := hashmap.NewComparable[sharing.ID, *Round1P2P[P, B, S]]()
	for id, message := range outgoingP2PMessages(c, uOut) {
		message.MulR1, err = c.State.AliceMul[id].Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run Alice mul round1")
		}
	}

	c.State.Round++
	return bOut, uOut.Freeze(), nil
}

func (c *Cosigner[P, B, S]) Round2(r1bOut network.RoundMessages[*Round1Broadcast], r1uOut network.RoundMessages[*Round1P2P[P, B, S]]) (r2bOut *Round2Broadcast[P, B, S], r2uOut network.RoundMessages[*Round2P2P[P, B, S]], err error) {
	incomingMessages, err := validateIncomingMessages(c, 2, r1bOut, r1uOut)
	if err != nil {
		return nil, nil, errs.NewFailed("invalid input or round mismatch")
	}

	zeroR1 := hashmap.NewComparable[sharing.ID, *przsSetup.Round1Broadcast]()
	mulR1 := make(map[sharing.ID]*mul_bbot.Round1P2P[P, S])
	for id, message := range incomingMessages {
		c.State.BigRCommitment[id] = message.broadcast.BigRCommitment
		zeroR1.Put(id, message.broadcast.ZeroSetupR1)
		mulR1[id] = message.p2p.MulR1
	}

	zeroR2, err := c.State.ZeroSetup.Round2(zeroR1.Freeze())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round2")
	}

	c.State.Chi = make(map[sharing.ID]S)
	bOut := &Round2Broadcast[P, B, S]{
		BigR:        c.State.BigR[c.MySharingId],
		BigRWitness: c.State.BigRWitness,
	}
	uOut := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id, message := range outgoingP2PMessages(c, uOut) {
		message.MulR2, c.State.Chi[id], err = c.State.BobMul[id].Round2(mulR1[id])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run bob mul round2")
		}
		message.ZeroSetupR2, _ = zeroR2.Get(id)
	}

	c.State.Round++
	return bOut, uOut.Freeze(), nil
}

func (c *Cosigner[P, B, S]) Round3(r2bOut network.RoundMessages[*Round2Broadcast[P, B, S]], r2uOut network.RoundMessages[*Round2P2P[P, B, S]]) (r3bOut *Round3Broadcast[P, B, S], r3uOut network.RoundMessages[*Round3P2P[P, B, S]], err error) {
	incomingMessages, err := validateIncomingMessages(c, 3, r2bOut, r2uOut)
	if err != nil {
		return nil, nil, errs.NewFailed("invalid input or round mismatch")
	}

	zeroR2 := hashmap.NewComparable[sharing.ID, *przsSetup.Round2P2P]()
	mulR2 := make(map[sharing.ID]*mul_bbot.Round2P2P[P, S])
	for id, message := range incomingMessages {
		if err := c.State.Ck.Verifier().Verify(c.State.BigRCommitment[id], message.broadcast.BigR.ToCompressed(), message.broadcast.BigRWitness); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, id, "invalid commitment")
		}
		c.State.BigR[id] = message.broadcast.BigR
		zeroR2.Put(id, message.p2p.ZeroSetupR2)
		mulR2[id] = message.p2p.MulR2
	}

	zeroSeeds, err := c.State.ZeroSetup.Round3(zeroR2.Freeze())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
	}
	c.State.Zero, err = przs.NewSampler(c.MySharingId, c.TheQuorum, zeroSeeds, c.Suite.ScalarField())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
	}
	zeta, err := c.State.Zero.Sample()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
	}

	//quorumSharingIds := slices.Collect(iterutils.Map(c.TheQuorum.Iter(), func(key types.IdentityKey) types.SharingID { id, _ := c.SharingCfg.Reverse().Get(key); return id }))
	//share := shamir.Share{
	//	Id:    c.MySharingId,
	//	Value: c.MyShard.SecretShare(),
	//}
	//c.State.Sk, err = share.ToAdditive(quorumSharingIds)

	// TODO: this function doesn't make sense
	quorum2, err := sharing.NewMinimalQualifiedAccessStructure(c.TheQuorum)
	if err != nil {
		panic(err)
	}

	sk, err := c.MyShard.Share().ToAdditive(*quorum2)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "to additive share failed")
	}

	c.State.Sk = sk.Value().Add(zeta)
	c.State.Pk = make(map[sharing.ID]P)
	c.State.Pk[c.MySharingId] = c.Suite.Curve().ScalarBaseMul(c.State.Sk)
	c.State.C = make(map[sharing.ID][]S)

	bOut := &Round3Broadcast[P, B, S]{Pk: c.State.Pk[c.MySharingId]}
	uOut := hashmap.NewComparable[sharing.ID, *Round3P2P[P, B, S]]()
	for id, message := range outgoingP2PMessages(c, uOut) {
		message.MulR3, c.State.C[id], err = c.State.AliceMul[id].Round3(mulR2[id], []S{c.State.R, c.State.Sk})
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run alice mul round3")
		}
		message.GammaU = c.Suite.Curve().ScalarBaseMul(c.State.C[id][0])
		message.GammaV = c.Suite.Curve().ScalarBaseMul(c.State.C[id][1])
		message.Psi = c.State.Phi.Sub(c.State.Chi[id])
	}

	c.State.Round++
	return bOut, uOut.Freeze(), nil
}

func (c *Cosigner[P, B, S]) Round4(r3bOut network.RoundMessages[*Round3Broadcast[P, B, S]], r3uOut network.RoundMessages[*Round3P2P[P, B, S]], message []byte) (partialSignature *dkls23.PartialSignature[P, B, S], err error) {
	incomingMessages, err := validateIncomingMessages(c, 4, r3bOut, r3uOut)
	if err != nil {
		return nil, errs.WrapFailed(err, "invalid input or round mismatch")
	}

	psi := c.Suite.ScalarField().Zero()
	cudu := c.Suite.ScalarField().Zero()
	cvdv := c.Suite.ScalarField().Zero()
	for id, message := range incomingMessages {
		d, err := c.State.BobMul[id].Round4(message.p2p.MulR3)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run bob mul round4")
		}
		c.State.Pk[id] = message.broadcast.Pk

		if !c.State.BigR[id].ScalarMul(c.State.Chi[id]).Sub(message.p2p.GammaU).Equal(c.Suite.Curve().ScalarBaseMul(d[0])) {
			return nil, errs.NewFailed("consistency check failed")
		}
		if !message.broadcast.Pk.ScalarMul(c.State.Chi[id]).Sub(message.p2p.GammaV).Equal(c.Suite.Curve().ScalarBaseMul(d[1])) {
			return nil, errs.NewFailed("consistency check failed")
		}

		psi = psi.Add(message.p2p.Psi)
		cudu = cudu.Add(c.State.C[id][0].Add(d[0]))
		cvdv = cvdv.Add(c.State.C[id][1].Add(d[1]))
	}

	bigR := sliceutils.Fold(func(x, y P) P { return x.Add(y) }, c.Suite.Curve().OpIdentity(), slices.Collect(maps.Values(c.State.BigR))...)
	pk := sliceutils.Fold(func(x, y P) P { return x.Add(y) }, c.Suite.Curve().OpIdentity(), slices.Collect(maps.Values(c.State.Pk))...)
	if !pk.Equal(c.MyShard.PublicKey()) {
		return nil, errs.NewFailed("consistency check failed")
	}

	u := c.State.R.Mul(c.State.Phi.Add(psi)).Add(cudu)
	v := c.State.Sk.Mul(c.State.Phi.Add(psi)).Add(cvdv)
	m, err := messageToScalar(c, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute message scalar")
	}
	rx, err := c.Suite.ScalarField().FromWideBytes(bigR.Coordinates().Value()[0].Bytes()) // TODO: fingers crossed it returns affine x
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert to scalar")
	}
	w := m.Mul(c.State.Phi).Add(rx.Mul(v))

	partialSignature = dkls23.NewPartialSignature(c.State.BigR[c.MySharingId], u, w)
	return partialSignature, nil
}
