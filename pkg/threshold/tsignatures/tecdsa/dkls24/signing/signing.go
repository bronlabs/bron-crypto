package signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/mult"
)

type Participant interface {
	types.ThresholdSignatureParticipant
	SharingConfig() types.SharingConfig
	Prng() io.Reader
	SessionId() []byte
	Shard() *dkls24.Shard
}

// Multiplication contains corresponding participant objects for pairwise multiplication subProtocols.
type Multiplication struct {
	Alice *mult.Alice
	Bob   *mult.Bob

	_ ds.Incomparable
}

type SubProtocols struct {
	// use to get the secret key mask (zeta_i)
	ZeroShareSampling *sample.Participant
	// pairwise multiplication protocol i.e. each party acts as alice and bob against every party
	Multiplication ds.HashMap[types.IdentityKey, *Multiplication]

	_ ds.Incomparable
}

type SignerState struct {
	Phi_i                          curves.Scalar
	Sk_i                           curves.Scalar
	R_i                            curves.Scalar
	Zeta_i                         curves.Scalar
	BigR_i                         curves.Point
	Pk_i                           curves.Point
	Cu_i                           map[types.SharingID]curves.Scalar
	Cv_i                           map[types.SharingID]curves.Scalar
	Du_i                           map[types.SharingID]curves.Scalar
	Dv_i                           map[types.SharingID]curves.Scalar
	Psi_i                          map[types.SharingID]curves.Scalar
	Chi_i                          map[types.SharingID]curves.Scalar
	InstanceKeyWitness             map[types.SharingID]commitments.Witness
	ReceivedInstanceKeyCommitments map[types.SharingID]commitments.Commitment
	ReceivedBigR_i                 ds.HashMap[types.IdentityKey, curves.Point]
	Protocols                      *SubProtocols

	_ ds.Incomparable
}

type Round1Broadcast struct {
	BigR_i curves.Point

	_ ds.Incomparable
}

type Round1P2P struct {
	InstanceKeyCommitment commitments.Commitment
	MultiplicationOutput  *mult.Round1Output

	_ ds.Incomparable
}

type Round2P2P struct {
	Multiplication     *mult.Round2Output
	GammaU_ij          curves.Point
	GammaV_ij          curves.Point
	Psi_ij             curves.Scalar
	InstanceKeyWitness commitments.Witness

	_ ds.Incomparable
}

type Round2Broadcast struct {
	Pk_i curves.Point

	_ ds.Incomparable
}

func DoRound1(p Participant, protocol types.ThresholdProtocol, sessionParticipants ds.HashSet[types.IdentityKey], state *SignerState) (*Round1Broadcast, types.RoundMessages[*Round1P2P], error) {
	var err error

	// step 1.1
	state.Phi_i, err = protocol.Curve().ScalarField().Random(p.Prng())
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not sample phi_i")
	}
	// step 1.2
	state.R_i, err = protocol.Curve().ScalarField().Random(p.Prng())
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not sample r_i")
	}
	// step 1.3
	state.BigR_i = protocol.Curve().ScalarBaseMult(state.R_i)

	state.InstanceKeyWitness = make(map[types.SharingID]commitments.Witness)
	state.Chi_i = make(map[types.SharingID]curves.Scalar)
	outputP2P := types.NewRoundMessages[*Round1P2P]()
	for participant := range sessionParticipants.Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.SharingConfig().LookUpRight(participant)
		if !exists {
			return nil, nil, errs.NewMissing("could not find sharing id of %x", participant.PublicKey())
		}

		// step 1.3.1
		commitmentToInstanceKey, witness, err := commitments.Commit(
			p.SessionId(),
			p.Prng(),
			bitstring.ToBytesLE(int(p.SharingId())),
			bitstring.ToBytesLE(int(sharingId)),
			state.BigR_i.ToAffineCompressed(),
		)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not commit to instance key")
		}
		state.InstanceKeyWitness[sharingId] = witness

		// step 1.3.2
		multInstance, exists := state.Protocols.Multiplication.Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("could not find multiplication instance for %x", participant.PublicKey())
		}
		b, multiplicationOutput, err := multInstance.Bob.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "multiplication round 1")
		}

		// step 1.3.3
		state.Chi_i[sharingId] = b

		// step 1.3.4
		outputP2P.Put(participant, &Round1P2P{
			InstanceKeyCommitment: commitmentToInstanceKey,
			MultiplicationOutput:  multiplicationOutput,
		})
	}

	outputBroadcast := &Round1Broadcast{
		BigR_i: state.BigR_i,
	}

	// step 1.4
	return outputBroadcast, outputP2P, nil
}

func DoRound2(p Participant, protocol types.ThresholdProtocol, sessionParticipants ds.HashSet[types.IdentityKey], state *SignerState, inputBroadcast types.RoundMessages[*Round1Broadcast], inputP2P types.RoundMessages[*Round1P2P]) (*Round2Broadcast, types.RoundMessages[*Round2P2P], error) {
	// step 2.1
	zeta_i, err := state.Protocols.ZeroShareSampling.Sample()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "mask F_Zero (sample)")
	}
	state.Zeta_i = zeta_i

	// step 2.2
	myAdditiveShare, err := p.Shard().SigningKeyShare.ToAdditive(p.IdentityKey(), sessionParticipants, protocol)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not convert my shamir share to additive share")
	}

	// step 2.3
	state.Sk_i = myAdditiveShare.Add(zeta_i)

	// step 2.4
	state.Pk_i = protocol.Curve().ScalarBaseMult(state.Sk_i)

	// step 2.5
	a := [mult.L]curves.Scalar{state.R_i, state.Sk_i}

	state.ReceivedBigR_i = hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	state.ReceivedInstanceKeyCommitments = make(map[types.SharingID]commitments.Commitment)
	state.Cu_i = make(map[types.SharingID]curves.Scalar)
	state.Cv_i = make(map[types.SharingID]curves.Scalar)
	outputP2P := types.NewRoundMessages[*Round2P2P]()
	for participant := range sessionParticipants.Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.SharingConfig().LookUpRight(participant)
		if !exists {
			return nil, nil, errs.NewMissing("could not find sharing id of %x", participant.PublicKey())
		}

		// step 2.6.1
		receivedBroadcastMessage, exists := inputBroadcast.Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("did not get a broadcasted message from id %d", sharingId)
		}
		state.ReceivedBigR_i.Put(participant, receivedBroadcastMessage.BigR_i)

		// step 2.6.2
		receivedP2PMessage, exists := inputP2P.Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("did not get a p2p message from id %d", sharingId)
		}
		state.ReceivedInstanceKeyCommitments[sharingId] = receivedP2PMessage.InstanceKeyCommitment

		// step 2.6.3
		multInstance, exists := state.Protocols.Multiplication.Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("could not find multiplication instance for %x", participant.PublicKey())
		}
		c_ij, multiplicationOutput, err := multInstance.Alice.Round2(receivedP2PMessage.MultiplicationOutput, a)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "F_RVOLE round 2 sample")
		}
		state.Cu_i[sharingId] = c_ij[0]
		state.Cv_i[sharingId] = c_ij[1]

		// step 2.6.4
		gammaU_ij := protocol.Curve().ScalarBaseMult(state.Cu_i[sharingId])

		// step 2.6.5
		gammaV_ij := protocol.Curve().ScalarBaseMult(state.Cv_i[sharingId])

		// step 2.6.6
		psi_ij := state.Phi_i.Sub(state.Chi_i[sharingId])

		// step 2.6.7
		outputP2P.Put(participant, &Round2P2P{
			Multiplication:     multiplicationOutput,
			GammaU_ij:          gammaU_ij,
			GammaV_ij:          gammaV_ij,
			Psi_ij:             psi_ij,
			InstanceKeyWitness: state.InstanceKeyWitness[sharingId],
		})
	}

	outputBroadcast := &Round2Broadcast{
		Pk_i: state.Pk_i,
	}

	// step 2.7
	return outputBroadcast, outputP2P, nil
}

func DoRound3Prologue(p Participant, protocol types.ThresholdProtocol, sessionParticipants ds.HashSet[types.IdentityKey], state *SignerState, inputBroadcast types.RoundMessages[*Round2Broadcast], inputP2P types.RoundMessages[*Round2P2P]) (err error) {
	state.Du_i = make(map[types.SharingID]curves.Scalar)
	state.Dv_i = make(map[types.SharingID]curves.Scalar)
	state.Psi_i = make(map[types.SharingID]curves.Scalar)
	refreshedPublicKey := state.Pk_i // this has zeta_i added so different from the one from public key share map
	for participant := range sessionParticipants.Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.SharingConfig().LookUpRight(participant)
		if !exists {
			return errs.NewMissing("could not find sharing id of %x", participant.PublicKey())
		}

		// step 3.1.1
		receivedBroadcastMessage, exists := inputBroadcast.Get(participant)
		if !exists {
			return errs.NewMissing("did not get a broadcasted message from id %d", sharingId)
		}
		pk_j := receivedBroadcastMessage.Pk_i

		// step 3.1.2
		receivedP2PMessage, exists := inputP2P.Get(participant)
		if !exists {
			return errs.NewMissing("did not get a p2p message from id %d", sharingId)
		}
		GammaU_ji := receivedP2PMessage.GammaU_ij
		GammaV_ji := receivedP2PMessage.GammaV_ij

		// step 3.1.3
		receivedBigR_i, exists := state.ReceivedBigR_i.Get(participant)
		if !exists {
			return errs.NewMissing("do not have BigRI in memory for %x", participant.PublicKey())
		}
		if err := commitments.Open(
			p.SessionId(),
			state.ReceivedInstanceKeyCommitments[sharingId],
			receivedP2PMessage.InstanceKeyWitness,
			bitstring.ToBytesLE(int(sharingId)),
			bitstring.ToBytesLE(int(p.SharingId())),
			receivedBigR_i.ToAffineCompressed(),
		); err != nil {
			return errs.WrapTotalAbort(err, sharingId, "message could not be opened")
		}

		// step 3.1.4
		multInstance, exists := state.Protocols.Multiplication.Get(participant)
		if !exists {
			return errs.NewMissing("could not find multiplication instance for %x", participant.PublicKey())
		}
		d_ij, err := multInstance.Bob.Round3(receivedP2PMessage.Multiplication)
		if err != nil {
			return errs.WrapTotalAbort(err, sharingId, "bob round 3")
		}
		du_ij := d_ij[0]
		dv_ij := d_ij[1]

		Chi_ij := state.Chi_i[sharingId]
		// step 3.1.5
		R_j, exists := state.ReceivedBigR_i.Get(participant)
		if !exists {
			return errs.NewMissing("do not have Rj in memory for j=%d", sharingId)
		}
		lhs1 := R_j.Mul(Chi_ij).Sub(GammaU_ji)
		rhs1 := protocol.Curve().ScalarBaseMult(du_ij)
		if !lhs1.Equal(rhs1) {
			return errs.NewTotalAbort(sharingId, "failed first check")
		}

		// step 3.1.6
		lhs2 := pk_j.Mul(Chi_ij).Sub(GammaV_ji)
		rhs2 := protocol.Curve().ScalarBaseMult(dv_ij)
		if !lhs2.Equal(rhs2) {
			return errs.NewTotalAbort(sharingId, "failed second check")
		}

		refreshedPublicKey = refreshedPublicKey.Add(pk_j)

		// We're partially evaluating what we need for future steps inside of this loop
		state.Du_i[sharingId] = du_ij
		state.Dv_i[sharingId] = dv_ij
		state.Psi_i[sharingId] = receivedP2PMessage.Psi_ij
	}

	// step 3.2
	if !refreshedPublicKey.Equal(p.Shard().SigningKeyShare.PublicKey) {
		return errs.NewTotalAbort(nil, "recomputed public key is wrong")
	}

	return nil
}

func DoRound3Epilogue(p Participant, protocol types.ThresholdSignatureProtocol, sessionParticipants ds.HashSet[types.IdentityKey], message []byte, r, sk, phi curves.Scalar, cu, cv, du, dv, psi map[types.SharingID]curves.Scalar, bigRs ds.HashMap[types.IdentityKey, curves.Point]) (*dkls24.PartialSignature, error) {
	R := r.ScalarField().Curve().ScalarBaseMult(r)
	phiPsi := phi
	cUdU := phi.ScalarField().Zero()
	cVdV := phi.ScalarField().Zero()
	for participant := range sessionParticipants.Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.SharingConfig().LookUpRight(participant)
		if !exists {
			return nil, errs.NewMissing("could not find sharing id of %x", participant.PublicKey())
		}
		// step 3.3
		cu_ij := cu[sharingId]
		cv_ij := cv[sharingId]
		du_ij := du[sharingId]
		dv_ij := dv[sharingId]
		phiPsi = phiPsi.Add(psi[sharingId])
		cUdU = cUdU.Add(cu_ij).Add(du_ij)
		cVdV = cVdV.Add(cv_ij).Add(dv_ij)
		Rj, exists := bigRs.Get(participant)
		if !exists {
			return nil, errs.NewMissing("no Rj for j=%d", sharingId)
		}
		R = R.Add(Rj)
	}

	// step 3.4
	u_i := r.Mul(phiPsi).Add(cUdU)

	// step 3.5
	v_i := sk.Mul(phiPsi).Add(cVdV)

	// step 3.6
	rx := protocol.CipherSuite().Curve().Scalar().SetNat(R.AffineX().Nat())
	digest, err := hashing.Hash(protocol.CipherSuite().Hash(), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "digest")
	}
	digestScalar, err := protocol.CipherSuite().Curve().Scalar().SetBytesWide(digest)
	if err != nil {
		return nil, errs.WrapFailed(err, "digestScalar")
	}
	w_i := digestScalar.Mul(phi).Add(rx.Mul(v_i))

	// step 3.7
	return &dkls24.PartialSignature{
		Ui: u_i,
		Wi: w_i,
		Ri: r.ScalarField().Curve().ScalarBaseMult(r),
	}, nil
}

// Aggregate computes the sum of partial signatures to get a valid signature. It also normalises the signature to the low-s form as well as attaches the recovery id to the final signature.
func Aggregate(cipherSuite types.SignatureProtocol, publicKey curves.Point, partialSignatures types.RoundMessages[*dkls24.PartialSignature], message []byte) (*ecdsa.Signature, error) {
	curve := cipherSuite.Curve()
	w := curve.ScalarField().Zero()
	u := curve.ScalarField().Zero()
	R := curve.Identity()
	for pair := range partialSignatures.Iter() {
		partialSignature := pair.Value
		w = w.Add(partialSignature.Wi)
		u = u.Add(partialSignature.Ui)
		R = R.Add(partialSignature.Ri)
	}

	// step 4.2
	rx := curve.Scalar().SetNat(R.AffineX().Nat())
	// step 4.3
	s := w.Div(u)
	// step 4.4
	v, err := ecdsa.CalculateRecoveryId(R)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute recovery id")
	}
	// step 4.5
	sigma := &ecdsa.Signature{V: &v, R: rx, S: s}
	// step 4.6
	sigma.Normalise()
	// step 4.7
	if err := ecdsa.Verify(sigma, cipherSuite.Hash(), publicKey, message); err != nil {
		return nil, errs.WrapVerification(err, "sigma is invalid")
	}
	// step 4.8
	return sigma, nil
}
