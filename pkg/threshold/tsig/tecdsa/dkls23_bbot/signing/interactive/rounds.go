package interactive

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// import (
//
//	"maps"
//	"slices"
//
//	"github.com/bronlabs/bron-crypto/pkg/base/curves"
//	"github.com/bronlabs/bron-crypto/pkg/base/errs"
//	"github.com/bronlabs/bron-crypto/pkg/base/types"
//	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
//	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
//	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
//	"github.com/bronlabs/bron-crypto/pkg/csprng/fkechacha20"
//	"github.com/bronlabs/bron-crypto/pkg/network"
//	bbotMul "github.com/bronlabs/bron-crypto/pkg/threshold/mult/dkls23_bbot"
//	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
//	zeroSample "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/sample"
//	zeroSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/setup"
//	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
//
// )
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

	//c.State.R, err = c.Protocol.Curve().ScalarField().Random(c.Prng)
	c.State.R, err = c.ScalarField.Random(c.Prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample r")
	}
	c.State.BigR = make(map[sharing.ID]P)
	c.State.BigR[c.MySharingId] = c.Curve.ScalarBaseMul(c.State.R)
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
	for party, message := range outgoingP2PMessages(c, r1uOut) {
		message.MulR1, err = c.State.AliceMul[party.id].Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run Alice mul round1")
		}
		message.ZeroSetupR1, _ = zeroR1.Get(party.key)
	}

	c.State.Round++
	return r1bOut, r1uOut, nil
}

//func (c *Cosigner) Round2(r1bOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round1Broadcast], r1uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round1P2P]) (r2bOut *Round2Broadcast, r2uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round2P2P], err error) {
//	incomingMessages, err := validateIncomingMessages(c, 2, r1bOut, r1uOut)
//	if err != nil {
//		return nil, nil, errs.NewFailed("invalid input or round mismatch")
//	}
//
//	zeroR1 := network.NewRoundMessages[types.Protocol, *zeroSetup.Round1P2P]()
//	mulR1 := make(map[types.SharingID]*bbotMul.Round1P2P)
//	for party, message := range incomingMessages {
//		c.State.BigRCommitment[party.id] = message.broadcast.BigRCommitment
//		zeroR1.Put(party.key, message.p2p.ZeroSetupR1)
//		mulR1[party.id] = message.p2p.MulR1
//	}
//
//	zeroR2, err := c.State.ZeroSetup.Round2(zeroR1)
//	if err != nil {
//		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round2")
//	}
//
//	c.State.Chi = make(map[types.SharingID]curves.Scalar)
//	r2bOut = &Round2Broadcast{
//		BigR:        c.State.BigR[c.MySharingId],
//		BigRWitness: c.State.BigRWitness,
//	}
//	r2uOut = network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round2P2P]()
//	for party, message := range outgoingP2PMessages(c, r2uOut) {
//		message.MulR2, c.State.Chi[party.id], err = c.State.BobMul[party.id].Round2(mulR1[party.id])
//		if err != nil {
//			return nil, nil, errs.WrapFailed(err, "cannot run bob mul round2")
//		}
//		message.ZeroSetupR2, _ = zeroR2.Get(party.key)
//	}
//
//	c.State.Round++
//	return r2bOut, r2uOut, nil
//}
//
//func (c *Cosigner) Round3(r2bOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round2Broadcast], r2uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round2P2P]) (r3bOut *Round3Broadcast, r3uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round3P2P], err error) {
//	incomingMessages, err := validateIncomingMessages(c, 3, r2bOut, r2uOut)
//	if err != nil {
//		return nil, nil, errs.NewFailed("invalid input or round mismatch")
//	}
//
//	zeroR2 := network.NewRoundMessages[types.Protocol, *zeroSetup.Round2P2P]()
//	mulR2 := make(map[types.SharingID]*bbotMul.Round2P2P)
//	for party, message := range incomingMessages {
//		if err := c.State.Ck.Verify(c.State.BigRCommitment[party.id], message.broadcast.BigR.ToAffineCompressed(), message.broadcast.BigRWitness); err != nil {
//			return nil, nil, errs.WrapIdentifiableAbort(err, party.id, "invalid commitment")
//		}
//		c.State.BigR[party.id] = message.broadcast.BigR
//		zeroR2.Put(party.key, message.p2p.ZeroSetupR2)
//		mulR2[party.id] = message.p2p.MulR2
//	}
//
//	zeroSeeds, err := c.State.ZeroSetup.Round3(zeroR2)
//	if err != nil {
//		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
//	}
//	csprngFactory, err := fkechacha20.NewPrng(nil, nil)
//	if err != nil {
//		return nil, nil, errs.WrapFailed(err, "cannot create random prng")
//	}
//	c.State.Zero, err = zeroSample.NewParticipant(c.SessionId, c.MyAuthKey, zeroSeeds, c.Protocol, c.TheQuorum, csprngFactory)
//	if err != nil {
//		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
//	}
//	zeta, err := c.State.Zero.Sample()
//	if err != nil {
//		return nil, nil, errs.WrapFailed(err, "cannot run zero setup round3")
//	}
//
//	quorumSharingIds := slices.Collect(iterutils.Map(c.TheQuorum.Iter(), func(key types.IdentityKey) types.SharingID { id, _ := c.SharingCfg.Reverse().Get(key); return id }))
//	share := shamir.Share{
//		Id:    c.MySharingId,
//		Value: c.MyShard.SecretShare(),
//	}
//	c.State.Sk, err = share.ToAdditive(quorumSharingIds)
//	if err != nil {
//		return nil, nil, errs.WrapFailed(err, "to additive share failed")
//	}
//	c.State.Sk = c.State.Sk.Add(zeta)
//	c.State.Pk = make(map[types.SharingID]curves.Point)
//	c.State.Pk[c.MySharingId] = c.Protocol.Curve().ScalarBaseMult(c.State.Sk)
//	c.State.C = make(map[types.SharingID][]curves.Scalar)
//
//	r3bOut = &Round3Broadcast{Pk: c.State.Pk[c.MySharingId]}
//	r3uOut = network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round3P2P]()
//	for party, message := range outgoingP2PMessages(c, r3uOut) {
//		message.MulR3, c.State.C[party.id], err = c.State.AliceMul[party.id].Round3(mulR2[party.id], []curves.Scalar{c.State.R, c.State.Sk})
//		if err != nil {
//			return nil, nil, errs.WrapFailed(err, "cannot run alice mul round3")
//		}
//		message.GammaU = c.Protocol.Curve().ScalarBaseMult(c.State.C[party.id][0])
//		message.GammaV = c.Protocol.Curve().ScalarBaseMult(c.State.C[party.id][1])
//		message.Psi = c.State.Phi.Sub(c.State.Chi[party.id])
//	}
//
//	c.State.Round++
//	return r3bOut, r3uOut, nil
//}
//
//func (c *Cosigner) Round4(r3bOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round3Broadcast], r3uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round3P2P], message []byte) (partialSignature *dkls23.PartialSignature, err error) {
//	incomingMessages, err := validateIncomingMessages(c, 4, r3bOut, r3uOut)
//	if err != nil {
//		return nil, errs.WrapFailed(err, "invalid input or round mismatch")
//	}
//
//	psi := c.Protocol.Curve().ScalarField().Zero()
//	cudu := c.Protocol.Curve().ScalarField().Zero()
//	cvdv := c.Protocol.Curve().ScalarField().Zero()
//	for party, message := range incomingMessages {
//		d, err := c.State.BobMul[party.id].Round4(message.p2p.MulR3)
//		if err != nil {
//			return nil, errs.WrapFailed(err, "cannot run bob mul round4")
//		}
//		c.State.Pk[party.id] = message.broadcast.Pk
//
//		if !c.State.BigR[party.id].ScalarMul(c.State.Chi[party.id]).Sub(message.p2p.GammaU).Equal(c.Protocol.Curve().ScalarBaseMult(d[0])) {
//			return nil, errs.NewFailed("consistency check failed")
//		}
//		if !message.broadcast.Pk.ScalarMul(c.State.Chi[party.id]).Sub(message.p2p.GammaV).Equal(c.Protocol.Curve().ScalarBaseMult(d[1])) {
//			return nil, errs.NewFailed("consistency check failed")
//		}
//
//		psi = psi.Add(message.p2p.Psi)
//		cudu = cudu.Add(c.State.C[party.id][0].Add(d[0]))
//		cvdv = cvdv.Add(c.State.C[party.id][1].Add(d[1]))
//	}
//
//	bigR := sliceutils.Fold(func(x, y curves.Point) curves.Point { return x.Add(y) }, c.Protocol.Curve().AdditiveIdentity(), slices.Collect(maps.Values(c.State.BigR))...)
//	pk := sliceutils.Fold(func(x, y curves.Point) curves.Point { return x.Add(y) }, c.Protocol.Curve().AdditiveIdentity(), slices.Collect(maps.Values(c.State.Pk))...)
//	if !pk.Equal(c.MyShard.PublicKey()) {
//		return nil, errs.NewFailed("consistency check failed")
//	}
//
//	u := c.State.R.Mul(c.State.Phi.Add(psi)).Add(cudu)
//	v := c.State.Sk.Mul(c.State.Phi.Add(psi)).Add(cvdv)
//	m, err := messageToScalar(c, message)
//	if err != nil {
//		return nil, errs.WrapFailed(err, "cannot compute message scalar")
//	}
//	rx := c.Protocol.SigningSuite().Curve().ScalarField().Element().SetNat(bigR.AffineX().Nat())
//	w := m.Mul(c.State.Phi).Add(rx.Mul(v))
//
//	partialSignature = &dkls23.PartialSignature{
//		Ri: c.State.BigR[c.MySharingId],
//		Ui: u,
//		Wi: w,
//	}
//	return partialSignature, nil
//}
