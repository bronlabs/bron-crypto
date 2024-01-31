package signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/mult"
)

type Participant interface {
	dkls24.Participant
	GetSharingId() int
	GetIdentityHashToSharingId() map[types.IdentityHash]int
	GetPrng() io.Reader
	GetSessionId() []byte
	GetShard() *dkls24.Shard
}

// Multiplication contains corresponding participant objects for pairwise multiplication subProtocols.
type Multiplication struct {
	Alice *mult.Alice
	Bob   *mult.Bob

	_ types.Incomparable
}

type SubProtocols struct {
	// use to get the secret key mask (zeta_i)
	ZeroShareParticipant *hjky.Participant
	// pairwise multiplication protocol i.e. each party acts as alice and bob against every party
	Multiplication map[types.IdentityHash]*Multiplication

	_ types.Incomparable
}

type SignerState struct {
	Phi_i                          curves.Scalar
	Sk_i                           curves.Scalar
	R_i                            curves.Scalar
	Zeta_i                         curves.Scalar
	BigR_i                         curves.Point
	Pk_i                           curves.Point
	Cu_i                           map[types.IdentityHash]curves.Scalar
	Cv_i                           map[types.IdentityHash]curves.Scalar
	Du_i                           map[types.IdentityHash]curves.Scalar
	Dv_i                           map[types.IdentityHash]curves.Scalar
	Psi_i                          map[types.IdentityHash]curves.Scalar
	Chi_i                          map[types.IdentityHash]curves.Scalar
	InstanceKeyWitness             map[types.IdentityHash]commitments.Witness
	ReceivedInstanceKeyCommitments map[types.IdentityHash]commitments.Commitment
	ReceivedBigR_i                 map[types.IdentityHash]curves.Point
	Protocols                      *SubProtocols

	_ types.Incomparable
}

type Round1Broadcast struct {
	BigR_i          curves.Point
	ZeroShareOutput *hjky.Round1Broadcast

	_ types.Incomparable
}

type Round1P2P struct {
	InstanceKeyCommitment commitments.Commitment
	MultiplicationOutput  *mult.Round1Output
	ZeroShareOutput       *hjky.Round1P2P

	_ types.Incomparable
}

type Round2P2P struct {
	Multiplication     *mult.Round2Output
	GammaU_ij          curves.Point
	GammaV_ij          curves.Point
	Psi_ij             curves.Scalar
	InstanceKeyWitness commitments.Witness

	_ types.Incomparable
}

type Round2Broadcast struct {
	Pk_i curves.Point

	_ types.Incomparable
}

func DoRound1(p Participant, sessionParticipants *hashset.HashSet[integration.IdentityKey], state *SignerState) (*Round1Broadcast, map[types.IdentityHash]*Round1P2P, error) {
	var err error

	// step 1.1
	state.Phi_i, err = p.GetCohortConfig().CipherSuite.Curve.ScalarField().Random(p.GetPrng())
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "could not sample phi_i")
	}
	// step 1.2
	state.R_i, err = p.GetCohortConfig().CipherSuite.Curve.ScalarField().Random(p.GetPrng())
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "could not sample r_i")
	}
	// step 1.3
	state.BigR_i = p.GetCohortConfig().CipherSuite.Curve.ScalarBaseMult(state.R_i)

	zeroShareBroadcast, zeroShareUnicast, err := state.Protocols.ZeroShareParticipant.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run round 1 of zero sampling")
	}

	state.InstanceKeyWitness = make(map[types.IdentityHash]commitments.Witness)
	state.Chi_i = make(map[types.IdentityHash]curves.Scalar)
	outputP2P := make(map[types.IdentityHash]*Round1P2P, sessionParticipants.Len())
	for _, participant := range sessionParticipants.Iter() {
		if participant.PublicKey().Equal(p.GetAuthKey().PublicKey()) {
			continue
		}

		// step 1.3.1
		idHash := participant.Hash()
		commitmentToInstanceKey, witness, err := commitments.Commit(
			p.GetSessionId(),
			p.GetPrng(),
			bitstring.ToBytesLE(p.GetSharingId()),
			bitstring.ToBytesLE(p.GetIdentityHashToSharingId()[idHash]),
			state.BigR_i.ToAffineCompressed(),
		)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not commit to instance key")
		}
		state.InstanceKeyWitness[idHash] = witness

		// step 1.3.2
		b, multiplicationOutput, err := state.Protocols.Multiplication[idHash].Bob.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "multiplication round 1")
		}

		// step 1.3.3
		state.Chi_i[idHash] = b

		// step 1.3.4
		outputP2P[idHash] = &Round1P2P{
			InstanceKeyCommitment: commitmentToInstanceKey,
			MultiplicationOutput:  multiplicationOutput,
			ZeroShareOutput:       zeroShareUnicast[idHash],
		}
	}

	outputBroadcast := &Round1Broadcast{
		BigR_i:          state.BigR_i,
		ZeroShareOutput: zeroShareBroadcast,
	}

	// step 1.4
	return outputBroadcast, outputP2P, nil
}

func DoRound2(p Participant, sessionParticipants *hashset.HashSet[integration.IdentityKey], state *SignerState, inputBroadcast map[types.IdentityHash]*Round1Broadcast, inputP2P map[types.IdentityHash]*Round1P2P) (*Round2Broadcast, map[types.IdentityHash]*Round2P2P, error) {
	zeroShareInputBroadcast := make(map[types.IdentityHash]*hjky.Round1Broadcast)
	zeroShareInputUnicast := make(map[types.IdentityHash]*hjky.Round1P2P)
	for id := range sessionParticipants.Iter() {
		if id == p.GetAuthKey().Hash() {
			continue
		}
		zeroShareInputBroadcast[id] = inputBroadcast[id].ZeroShareOutput
		zeroShareInputUnicast[id] = inputP2P[id].ZeroShareOutput
	}

	// step 2.1
	zeta_i, _, _, err := state.Protocols.ZeroShareParticipant.Round2(zeroShareInputBroadcast, zeroShareInputUnicast)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "mask F_Zero (sample)")
	}
	// zeta_i is (t, t) sharing and has to be converted to (t, n) sharing
	state.Zeta_i, err = tsignatures.ShamirReShare(p.GetAuthKey(), zeta_i, sessionParticipants, sessionParticipants, p.GetCohortConfig().Participants)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "mask F_Zero (sample)")
	}

	// step 2.3
	state.Sk_i = p.GetShard().SigningKeyShare.Share.Add(state.Zeta_i)

	// step 2.4
	state.Pk_i = p.GetCohortConfig().CipherSuite.Curve.ScalarBaseMult(state.Sk_i)

	// step 2.5
	a := [mult.L]curves.Scalar{state.R_i, state.Sk_i}

	state.ReceivedBigR_i = make(map[types.IdentityHash]curves.Point)
	state.ReceivedInstanceKeyCommitments = make(map[types.IdentityHash]commitments.Commitment)
	state.Cu_i = make(map[types.IdentityHash]curves.Scalar)
	state.Cv_i = make(map[types.IdentityHash]curves.Scalar)
	outputP2P := make(map[types.IdentityHash]*Round2P2P)
	for _, participant := range sessionParticipants.Iter() {
		if participant.PublicKey().Equal(p.GetAuthKey().PublicKey()) {
			continue
		}

		// step 2.6.1
		idHash := participant.Hash()
		receivedBroadcastMessage := inputBroadcast[idHash]
		state.ReceivedBigR_i[idHash] = receivedBroadcastMessage.BigR_i

		// step 2.6.2
		receivedP2PMessage := inputP2P[idHash]
		state.ReceivedInstanceKeyCommitments[idHash] = receivedP2PMessage.InstanceKeyCommitment

		// step 2.6.3
		c_ij, multiplicationOutput, err := state.Protocols.Multiplication[idHash].Alice.Round2(receivedP2PMessage.MultiplicationOutput, a)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "F_RVOLE round 2 sample")
		}
		state.Cu_i[idHash] = c_ij[0]
		state.Cv_i[idHash] = c_ij[1]

		// step 2.6.4
		gammaU_ij := p.GetCohortConfig().CipherSuite.Curve.ScalarBaseMult(state.Cu_i[idHash])

		// step 2.6.5
		gammaV_ij := p.GetCohortConfig().CipherSuite.Curve.ScalarBaseMult(state.Cv_i[idHash])

		// step 2.6.6
		psi_ij := state.Phi_i.Sub(state.Chi_i[idHash])

		// step 2.6.7
		outputP2P[idHash] = &Round2P2P{
			Multiplication:     multiplicationOutput,
			GammaU_ij:          gammaU_ij,
			GammaV_ij:          gammaV_ij,
			Psi_ij:             psi_ij,
			InstanceKeyWitness: state.InstanceKeyWitness[idHash],
		}
	}

	outputBroadcast := &Round2Broadcast{
		Pk_i: state.Pk_i,
	}

	// step 2.7
	return outputBroadcast, outputP2P, nil
}

func DoRound3Prologue(p Participant, sessionParticipants *hashset.HashSet[integration.IdentityKey], state *SignerState, inputBroadcast map[types.IdentityHash]*Round2Broadcast, inputP2P map[types.IdentityHash]*Round2P2P) (err error) {
	lambda_i, err := tsignatures.ToAdditiveShare(p.GetCohortConfig().CipherSuite.Curve.ScalarField().One(), p.GetSharingId(), sessionParticipants, p.GetIdentityHashToSharingId())
	if err != nil {
		return errs.WrapFailed(err, "cannot calculate lambda")
	}

	state.Du_i = make(map[types.IdentityHash]curves.Scalar)
	state.Dv_i = make(map[types.IdentityHash]curves.Scalar)
	state.Psi_i = make(map[types.IdentityHash]curves.Scalar)
	refreshedPublicKey := state.Pk_i.Mul(lambda_i) // this has zeta_i added so different from the one from public key share map
	for _, participant := range sessionParticipants.Iter() {
		if participant.PublicKey().Equal(p.GetAuthKey().PublicKey()) {
			continue
		}

		// step 3.1.1
		idHash := participant.Hash()
		receivedBroadcastMessage, exists := inputBroadcast[idHash]
		if !exists {
			return errs.NewMissing("don't have broadcast message")
		}

		pk_j := receivedBroadcastMessage.Pk_i
		lambda_j, err := tsignatures.ToAdditiveShare(p.GetCohortConfig().CipherSuite.Curve.ScalarField().One(), p.GetIdentityHashToSharingId()[idHash], sessionParticipants, p.GetIdentityHashToSharingId())
		if err != nil {
			return errs.WrapFailed(err, "cannot convert to additive share")
		}
		pk_jAdditive := pk_j.Mul(lambda_j)

		// step 3.1.2
		receivedP2PMessage, exists := inputP2P[idHash]
		if !exists {
			return errs.NewMissing("don't have p2p message")
		}
		GammaU_ji := receivedP2PMessage.GammaU_ij
		GammaV_ji := receivedP2PMessage.GammaV_ij

		// step 3.1.3
		if err := commitments.Open(
			p.GetSessionId(),
			state.ReceivedInstanceKeyCommitments[idHash],
			receivedP2PMessage.InstanceKeyWitness,
			bitstring.ToBytesLE(p.GetIdentityHashToSharingId()[idHash]),
			bitstring.ToBytesLE(p.GetSharingId()),
			state.ReceivedBigR_i[idHash].ToAffineCompressed(),
		); err != nil {
			return errs.WrapTotalAbort(err, idHash, "message could not be opened")
		}

		// step 3.1.4
		d_ij, err := state.Protocols.Multiplication[idHash].Bob.Round3(receivedP2PMessage.Multiplication)
		if err != nil {
			return errs.WrapTotalAbort(err, idHash, "bob round 3")
		}
		du_ij := d_ij[0]
		dv_ij := d_ij[1]

		Chi_ij := state.Chi_i[idHash]
		// step 3.1.5
		R_j := state.ReceivedBigR_i[idHash]
		lhs1 := R_j.Mul(Chi_ij).Sub(GammaU_ji)
		rhs1 := p.GetCohortConfig().CipherSuite.Curve.ScalarBaseMult(du_ij)
		if !lhs1.Equal(rhs1) {
			return errs.NewTotalAbort(idHash, "failed first check")
		}

		// step 3.1.6
		lhs2 := pk_j.Mul(Chi_ij).Sub(GammaV_ji)
		rhs2 := p.GetCohortConfig().CipherSuite.Curve.ScalarBaseMult(dv_ij)
		if !lhs2.Equal(rhs2) {
			return errs.NewTotalAbort(idHash, "failed second check")
		}

		refreshedPublicKey = refreshedPublicKey.Add(pk_jAdditive)

		// We're partially evaluating what we need for future steps inside of this loop
		state.Du_i[idHash] = du_ij
		state.Dv_i[idHash] = dv_ij
		state.Psi_i[idHash] = receivedP2PMessage.Psi_ij
	}

	// step 3.2
	if !refreshedPublicKey.Equal(p.GetShard().SigningKeyShare.PublicKey) {
		return errs.NewTotalAbort(nil, "recomputed public key is wrong")
	}

	return nil
}

func DoRound3Epilogue(p Participant, sessionParticipants *hashset.HashSet[integration.IdentityKey], message []byte, r, sk, phi curves.Scalar, cu, cv, du, dv, psi map[types.IdentityHash]curves.Scalar, bigRs map[types.IdentityHash]curves.Point) (*dkls24.PartialSignature, error) {
	R := r.ScalarField().Curve().ScalarBaseMult(r)
	phiPsi := phi
	cUdU := phi.ScalarField().Zero()
	cVdV := phi.ScalarField().Zero()
	for _, participant := range sessionParticipants.Iter() {
		if participant.PublicKey().Equal(p.GetAuthKey().PublicKey()) {
			continue
		}

		cu_ij := cu[participant.Hash()]
		cv_ij := cv[participant.Hash()]
		cv_ijAdditive, err := tsignatures.ToAdditiveShare(cv_ij, p.GetSharingId(), sessionParticipants, p.GetIdentityHashToSharingId())
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot convert to additive share")
		}
		du_ij := du[participant.Hash()]
		dv_ij := dv[participant.Hash()]
		dv_ijAdditive, err := tsignatures.ToAdditiveShare(dv_ij, p.GetIdentityHashToSharingId()[participant.Hash()], sessionParticipants, p.GetIdentityHashToSharingId())
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot convert to additive share")
		}
		phiPsi = phiPsi.Add(psi[participant.Hash()])
		cUdU = cUdU.Add(cu_ij).Add(du_ij)
		cVdV = cVdV.Add(cv_ijAdditive).Add(dv_ijAdditive)
		R = R.Add(bigRs[participant.Hash()]) // step 3.3
	}

	// step 3.4
	u_i := r.Mul(phiPsi).Add(cUdU)
	// step 3.5
	phiPsiAdditive, err := tsignatures.ToAdditiveShare(phiPsi, p.GetSharingId(), sessionParticipants, p.GetIdentityHashToSharingId())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert to additive share")
	}
	v_i := sk.Mul(phiPsiAdditive).Add(cVdV)

	// step 3.6
	rx := p.GetCohortConfig().CipherSuite.Curve.Scalar().SetNat(R.AffineX().Nat())
	digest, err := hashing.Hash(p.GetCohortConfig().CipherSuite.Hash, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "digest")
	}
	digestScalar, err := p.GetCohortConfig().CipherSuite.Curve.Scalar().SetBytesWide(digest)
	if err != nil {
		return nil, errs.WrapFailed(err, "digestScalar")
	}
	// TODO: redo when FieldElement.Scalar is implemented
	w_i := digestScalar.Mul(phi).Add(rx.Mul(v_i))

	// step 3.7
	return &dkls24.PartialSignature{
		Ui: u_i,
		Wi: w_i,
		Ri: r.ScalarField().Curve().ScalarBaseMult(r),
	}, nil
}

// Aggregate computes the sum of partial signatures to get a valid signature. It also normalises the signature to the low-s form as well as attaches the recovery id to the final signature.
func Aggregate(cipherSuite *integration.CipherSuite, publicKey curves.Point, partialSignatures map[types.IdentityHash]*dkls24.PartialSignature, message []byte) (*ecdsa.Signature, error) {
	curve := cipherSuite.Curve
	w := curve.ScalarField().Zero()
	u := curve.ScalarField().Zero()
	R := curve.Identity()
	for _, partialSignature := range partialSignatures {
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
	if err := ecdsa.Verify(sigma, cipherSuite.Hash, publicKey, message); err != nil {
		return nil, errs.WrapVerificationFailed(err, "sigma is invalid")
	}
	// step 4.8
	return sigma, nil
}
