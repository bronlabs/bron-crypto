package interactive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/mult"
)

type Round1Broadcast struct {
	R_i curves.Point

	_ types.Incomparable
}

type Round1P2P struct {
	CommitmentToInstanceKey commitments.Commitment
	MultiplicationOutput    *mult.Round1Output

	_ types.Incomparable
}

type Round2P2P struct {
	Multiplication                      *mult.Round2Output
	GammaU_ij                           curves.Point
	GammaV_ij                           curves.Point
	Psi_ij                              curves.Scalar
	WitnessOfTheCommitmentToInstanceKey commitments.Witness

	_ types.Incomparable
}

type Round2Broadcast struct {
	PK_i curves.Point

	_ types.Incomparable
}

func (ic *Cosigner) Round1() (r1b *Round1Broadcast, r1u map[types.IdentityHash]*Round1P2P, err error) {
	if ic.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", ic.round)
	}
	// step 1.1
	ic.state.phi_i, err = ic.CohortConfig.CipherSuite.Curve.ScalarField().Random(ic.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "could not sample phi_i")
	}
	// step 1.2
	ic.state.r_i, err = ic.CohortConfig.CipherSuite.Curve.ScalarField().Random(ic.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "could not sample r_i")
	}
	// step 1.3
	ic.state.R_i = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.r_i)

	outputP2P := make(map[types.IdentityHash]*Round1P2P, ic.SessionParticipants.Len())
	for _, participant := range ic.SessionParticipants.Iter() {
		if participant.PublicKey().Equal(ic.MyAuthKey.PublicKey()) {
			continue
		}

		// step 1.3.1
		idHash := participant.Hash()
		commitmentToInstanceKey, witness, err := commitments.Commit(
			ic.UniqueSessionId,
			ic.prng,
			bitstring.ToBytesLE(ic.MyShamirId),
			bitstring.ToBytesLE(ic.IdentityKeyToShamirId[idHash]),
			ic.state.R_i.ToAffineCompressed(),
		)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not commit to instance key")
		}
		ic.state.witnessesOfCommitmentToInstanceKey[idHash] = witness

		// step 1.3.2
		b, multiplicationOutput, err := ic.subprotocols.multiplication[idHash].Bob.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "multiplication round 1")
		}

		// step 1.3.3
		ic.state.Chi_i[idHash] = b

		// step 1.3.4
		outputP2P[idHash] = &Round1P2P{
			CommitmentToInstanceKey: commitmentToInstanceKey,
			MultiplicationOutput:    multiplicationOutput,
		}
	}
	ic.round++
	// step 1.4
	return &Round1Broadcast{
		R_i: ic.state.R_i,
	}, outputP2P, nil
}

func (ic *Cosigner) Round2(round1outputBroadcast map[types.IdentityHash]*Round1Broadcast, round1outputP2P map[types.IdentityHash]*Round1P2P) (*Round2Broadcast, map[types.IdentityHash]*Round2P2P, error) {
	if ic.round != 2 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 2", ic.round)
	}
	// step 2.1
	zeta_i, err := ic.subprotocols.zeroShareSampling.Sample()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "mask F_Zero")
	}
	// step 2.2
	myShamirShare := &shamir.Share{
		Id:    ic.MyShamirId,
		Value: ic.Shard.SigningKeyShare.Share,
	}
	myAdditiveShare, err := myShamirShare.ToAdditive(ic.sessionShamirIDs)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not convert my shamir share to additive share")
	}
	// step 2.3
	ic.state.sk_i = myAdditiveShare.Add(zeta_i)
	// step 2.4
	ic.state.pk_i = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.sk_i)
	// step 2.5
	a := [mult.L]curves.Scalar{ic.state.r_i, ic.state.sk_i}

	outputP2P := make(map[types.IdentityHash]*Round2P2P)
	for _, participant := range ic.SessionParticipants.Iter() {
		if participant.PublicKey().Equal(ic.MyAuthKey.PublicKey()) {
			continue
		}
		// step 2.6.1
		idHash := participant.Hash()
		receivedBroadcastMessage := round1outputBroadcast[idHash]
		ic.state.receivedR_i[idHash] = receivedBroadcastMessage.R_i

		// step 2.6.2
		receivedP2PMessage := round1outputP2P[idHash]
		ic.state.receivedCommitmentsToInstanceKey[idHash] = receivedP2PMessage.CommitmentToInstanceKey

		// step 2.6.3
		c_ij, multiplicationOutput, err := ic.subprotocols.multiplication[idHash].Alice.Round2(receivedP2PMessage.MultiplicationOutput, a)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "F_RVOLE round 2 sample")
		}
		ic.state.cU_i[idHash] = c_ij[0]
		ic.state.cV_i[idHash] = c_ij[1]

		// step 2.6.4
		gammaU_ij := ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.cU_i[idHash])
		// step 2.6.5
		gammaV_ij := ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.cV_i[idHash])
		// step 2.6.6
		psi_ij := ic.state.phi_i.Sub(ic.state.Chi_i[idHash])

		// step 2.6.7
		outputP2P[idHash] = &Round2P2P{
			Multiplication:                      multiplicationOutput,
			GammaU_ij:                           gammaU_ij,
			GammaV_ij:                           gammaV_ij,
			Psi_ij:                              psi_ij,
			WitnessOfTheCommitmentToInstanceKey: ic.state.witnessesOfCommitmentToInstanceKey[idHash],
		}
	}
	ic.round++
	// step 2.7
	return &Round2Broadcast{
		PK_i: ic.state.pk_i,
	}, outputP2P, nil
}

func (ic *Cosigner) Round3(round2outputBroadcast map[types.IdentityHash]*Round2Broadcast, round2outputP2P map[types.IdentityHash]*Round2P2P, message []byte) (*dkls24.PartialSignature, error) {
	if ic.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", ic.round)
	}
	refreshedPublicKey := ic.state.pk_i // this has zeta_i added so different than the one from public key share map
	R := ic.state.R_i
	phiPsi := ic.state.phi_i
	cUdU := ic.CohortConfig.CipherSuite.Curve.ScalarField().Zero()
	cVdV := ic.CohortConfig.CipherSuite.Curve.ScalarField().Zero()

	for _, participant := range ic.SessionParticipants.Iter() {
		if participant.PublicKey().Equal(ic.MyAuthKey.PublicKey()) {
			continue
		}
		// step 3.1.1
		idHash := participant.Hash()
		receivedBroadcastedMessage, exists := round2outputBroadcast[idHash]
		if !exists {
			return nil, errs.NewMissing("don't have broadcast message")
		}
		pk_j := receivedBroadcastedMessage.PK_i

		// step 3.1.2
		receivedP2PMessage, exists := round2outputP2P[idHash]
		if !exists {
			return nil, errs.NewMissing("don't have p2p message")
		}
		GammaU_ji := receivedP2PMessage.GammaU_ij
		GammaV_ji := receivedP2PMessage.GammaV_ij

		// step 3.1.3
		if err := commitments.Open(ic.UniqueSessionId, ic.state.receivedCommitmentsToInstanceKey[idHash], receivedP2PMessage.WitnessOfTheCommitmentToInstanceKey, bitstring.ToBytesLE(ic.IdentityKeyToShamirId[idHash]), bitstring.ToBytesLE(ic.MyShamirId), ic.state.receivedR_i[idHash].ToAffineCompressed()); err != nil {
			return nil, errs.WrapTotalAbort(err, idHash, "message could not be opened")
		}

		// step 3.1.4
		d_ij, err := ic.subprotocols.multiplication[idHash].Bob.Round3(receivedP2PMessage.Multiplication)
		if err != nil {
			return nil, errs.WrapTotalAbort(err, idHash, "bob round 3")
		}
		du_ij := d_ij[0]
		dv_ij := d_ij[1]

		Chi_ij := ic.state.Chi_i[idHash]
		// step 3.1.5
		R_j := ic.state.receivedR_i[idHash]
		lhs1 := R_j.Mul(Chi_ij).Sub(GammaU_ji)
		rhs1 := ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(du_ij)
		if !lhs1.Equal(rhs1) {
			return nil, errs.NewTotalAbort(idHash, "failed first check")
		}

		// step 3.1.6
		P_j := pk_j
		llhs := P_j.Mul(Chi_ij)
		lhs2 := llhs.Sub(GammaV_ji)
		rhs := ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(dv_ij)
		if !lhs2.Equal(rhs) {
			return nil, errs.NewTotalAbort(idHash, "failed second check")
		}

		refreshedPublicKey = refreshedPublicKey.Add(pk_j)
		// We're partially evaluating what we need for future steps inside of this loop
		cu_ij := ic.state.cU_i[idHash]
		cv_ij := ic.state.cV_i[idHash]
		phiPsi = phiPsi.Add(round2outputP2P[idHash].Psi_ij)
		cUdU = cUdU.Add(cu_ij).Add(du_ij)
		cVdV = cVdV.Add(cv_ij).Add(dv_ij)
		R = R.Add(R_j) // step 3.3
	}

	// step 3.2
	if !refreshedPublicKey.Equal(ic.Shard.SigningKeyShare.PublicKey) {
		return nil, errs.NewTotalAbort(nil, "recomputed public key is wrong")
	}

	// step 3.4
	u_i := ic.state.r_i.Mul(phiPsi).Add(cUdU)
	// step 3.5
	v_i := ic.state.sk_i.Mul(phiPsi).Add(cVdV)

	// step 3.6
	rx := ic.CohortConfig.CipherSuite.Curve.Scalar().SetNat(R.AffineX().Nat())
	digest, err := hashing.Hash(ic.CohortConfig.CipherSuite.Hash, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "digest")
	}
	digestScalar, err := ic.CohortConfig.CipherSuite.Curve.Scalar().SetBytesWide(digest)
	if err != nil {
		return nil, errs.WrapFailed(err, "digestScalar")
	}
	// TODO: redo when FieldElement.Scalar is implemented
	w_i := digestScalar.Mul(ic.state.phi_i).Add(rx.Mul(v_i))

	ic.round++
	// step 3.7
	return &dkls24.PartialSignature{
		Ui: u_i,
		Wi: w_i,
		Ri: ic.state.R_i,
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
