package interactive

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	zeroSample "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/sample"
	zeroSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/setup"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
)

func (c *Cosigner) Round1() (r1bOut *Round1Broadcast, r1uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round1P2P], err error) {
	// todo validation

	var ck [32]byte
	ckBytes, err := c.Tape.ExtractBytes(ckLabel, uint(len(ck)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to extract commitment key")
	}
	copy(ck[:], ckBytes)
	c.State.Ck = hash_comm.NewCommittingKey(ck)

	c.State.R, err = c.Protocol.Curve().ScalarField().Random(c.Prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample r")
	}
	c.State.BigR = make(map[types.SharingID]curves.Point)
	c.State.BigR[c.MySharingId] = c.Protocol.Curve().ScalarBaseMult(c.State.R)
	c.State.BigRCommitment = make(map[types.SharingID]hash_comm.Commitment)
	c.State.BigRCommitment[c.MySharingId], c.State.BigRWitness, err = c.State.Ck.Commit(c.State.BigR[c.MySharingId].ToAffineCompressed(), c.Prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit to r")
	}

	c.State.Phi, err = c.Protocol.Curve().ScalarField().Random(c.Prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample phi")
	}

	zeroR1, err := c.State.ZeroSetup.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot round 1 of zero setup")
	}

	r1bOut = &Round1Broadcast{BigRCommitment: c.State.BigRCommitment[c.MySharingId]}
	r1uOut = network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round1P2P]()
	for id, key := range c.otherCosigners() {
		r1u := new(Round1P2P)
		r1u.MulR1, err = c.State.AliceMul[id].Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run Alice mul round1")
		}
		r1u.ZeroSetupR1, _ = zeroR1.Get(key)
		r1uOut.Put(key, r1u)
	}

	return r1bOut, r1uOut, nil
}

func (c *Cosigner) Round2(r1bOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round1Broadcast], r1uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round1P2P]) (r2bOut *Round2Broadcast, r2uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round2P2P], err error) {
	// todo validation

	zeroR1 := network.NewRoundMessages[types.Protocol, *zeroSetup.Round1P2P]()
	for id, key := range c.otherCosigners() {
		r1b, _ := r1bOut.Get(key)
		r1u, _ := r1uOut.Get(key)
		c.State.BigRCommitment[id] = r1b.BigRCommitment
		zeroR1.Put(key, r1u.ZeroSetupR1)
	}

	zeroR2, err := c.State.ZeroSetup.Round2(zeroR1)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round2")
	}

	c.State.Chi = make(map[types.SharingID]curves.Scalar)
	r2bOut = &Round2Broadcast{
		BigR:        c.State.BigR[c.MySharingId],
		BigRWitness: c.State.BigRWitness,
	}
	r2uOut = network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round2P2P]()
	for id, key := range c.otherCosigners() {
		uIn, _ := r1uOut.Get(key)
		uOut := new(Round2P2P)
		uOut.MulR2, c.State.Chi[id], err = c.State.BobMul[id].Round2(uIn.MulR1)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run bob mul round2")
		}
		uOut.ZeroSetupR2, _ = zeroR2.Get(key)
		r2uOut.Put(key, uOut)
	}

	return r2bOut, r2uOut, nil
}

func (c *Cosigner) Round3(r2bOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round2Broadcast], r2uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round2P2P]) (r3bOut *Round3Broadcast, r3uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round3P2P], err error) {
	zeroR2 := network.NewRoundMessages[types.Protocol, *zeroSetup.Round2P2P]()
	for id, key := range c.otherCosigners() {
		r2b, _ := r2bOut.Get(key)
		r2u, _ := r2uOut.Get(key)
		if err := c.State.Ck.Verify(c.State.BigRCommitment[id], r2b.BigR.ToAffineCompressed(), r2b.BigRWitness); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, id, "invalid commitment")
		}
		c.State.BigR[id] = r2b.BigR
		zeroR2.Put(key, r2u.ZeroSetupR2)
	}

	zeroSeeds, err := c.State.ZeroSetup.Round3(zeroR2)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
	}
	csprngFactory, err := fkechacha20.NewPrng(nil, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create random prng")
	}
	c.State.Zero, err = zeroSample.NewParticipant(c.SessionId, c.MyAuthKey, zeroSeeds, c.Protocol, c.TheQuorum, csprngFactory)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
	}
	zeta, err := c.State.Zero.Sample()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
	}

	quorumSharingIds := slices.Collect(iterutils.Map(c.TheQuorum.Iter(), func(key types.IdentityKey) types.SharingID { id, _ := c.SharingCfg.Reverse().Get(key); return id }))
	share := shamir.Share{
		Id:    c.MySharingId,
		Value: c.MyShard.SecretShare(),
	}
	c.State.Sk, err = share.ToAdditive(quorumSharingIds)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "to additive share failed")
	}
	c.State.Sk = c.State.Sk.Add(zeta)
	c.State.Pk = make(map[types.SharingID]curves.Point)
	c.State.Pk[c.MySharingId] = c.Protocol.Curve().ScalarBaseMult(c.State.Sk)
	c.State.C = make(map[types.SharingID][]curves.Scalar)

	r3bOut = &Round3Broadcast{Pk: c.State.Pk[c.MySharingId]}
	r3uOut = network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round3P2P]()
	for id, key := range c.otherCosigners() {
		r2u, _ := r2uOut.Get(key)
		r3 := new(Round3P2P)
		r3.MulR3, c.State.C[id], err = c.State.AliceMul[id].Round3(r2u.MulR2, []curves.Scalar{c.State.R, c.State.Sk})
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run alice mul round3")
		}
		r3.GammaU = c.Protocol.Curve().ScalarBaseMult(c.State.C[id][0])
		r3.GammaV = c.Protocol.Curve().ScalarBaseMult(c.State.C[id][1])
		r3.Psi = c.State.Phi.Sub(c.State.Chi[id])
		r3uOut.Put(key, r3)
	}

	return r3bOut, r3uOut, nil
}

func (c *Cosigner) Round4(r3bOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round3Broadcast], r3uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round3P2P], message []byte) (partialSignature *dkls23.PartialSignature, err error) {
	psi := c.Protocol.Curve().ScalarField().Zero()
	cudu := c.Protocol.Curve().ScalarField().Zero()
	cvdv := c.Protocol.Curve().ScalarField().Zero()
	for id, key := range c.otherCosigners() {
		bIn, _ := r3bOut.Get(key)
		uIn, _ := r3uOut.Get(key)
		d, err := c.State.BobMul[id].Round4(uIn.MulR3)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run bob mul round4")
		}
		c.State.Pk[id] = bIn.Pk

		if !c.State.BigR[id].ScalarMul(c.State.Chi[id]).Sub(uIn.GammaU).Equal(c.Protocol.Curve().ScalarBaseMult(d[0])) {
			return nil, errs.NewFailed("consistency check failed")
		}
		if !bIn.Pk.ScalarMul(c.State.Chi[id]).Sub(uIn.GammaV).Equal(c.Protocol.Curve().ScalarBaseMult(d[1])) {
			return nil, errs.NewFailed("consistency check failed")
		}

		psi = psi.Add(uIn.Psi)
		cudu = cudu.Add(c.State.C[id][0].Add(d[0]))
		cvdv = cvdv.Add(c.State.C[id][1].Add(d[1]))
	}

	bigR := sliceutils.Fold(func(x, y curves.Point) curves.Point { return x.Add(y) }, c.Protocol.Curve().AdditiveIdentity(), slices.Collect(maps.Values(c.State.BigR))...)
	pk := sliceutils.Fold(func(x, y curves.Point) curves.Point { return x.Add(y) }, c.Protocol.Curve().AdditiveIdentity(), slices.Collect(maps.Values(c.State.Pk))...)
	if !pk.Equal(c.MyShard.PublicKey()) {
		return nil, errs.NewFailed("consistency check failed")
	}

	u := c.State.R.Mul(c.State.Phi.Add(psi)).Add(cudu)
	v := c.State.Sk.Mul(c.State.Phi.Add(psi)).Add(cvdv)
	m, err := c.messageToScalar(message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute message scalar")
	}
	rx := c.Protocol.SigningSuite().Curve().ScalarField().Element().SetNat(bigR.AffineX().Nat())
	w := m.Mul(c.State.Phi).Add(rx.Mul(v))

	partialSignature = &dkls23.PartialSignature{
		Ri: c.State.BigR[c.MySharingId],
		Ui: u,
		Wi: w,
	}
	return partialSignature, nil
}

func (c *Cosigner) messageToScalar(message []byte) (curves.Scalar, error) {
	messageHash, err := hashing.Hash(c.Protocol.SigningSuite().Hash(), message)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash message")
	}
	mPrimeUint := ecdsa.BitsToInt(messageHash, c.Protocol.Curve())
	mPrime, err := c.Protocol.Curve().ScalarField().Element().SetBytes(mPrimeUint.Bytes())
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot convert message to scalar")
	}
	return mPrime, nil
}
