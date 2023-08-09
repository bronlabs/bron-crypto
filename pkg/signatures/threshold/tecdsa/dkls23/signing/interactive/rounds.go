package interactive

import (
	"bytes"
	"math/big"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/mult"
)

var h = sha3.New256

type Round1Broadcast struct {
	R_i curves.Point
}

type Round1P2P struct {
	CommitmentToInstanceKey commitments.Commitment
	MultiplicationOutput    *mult.Round1Output
}

type Round2P2P struct {
	Multiplication                      *mult.Round2Output
	GammaU_ij                           curves.Point
	GammaV_ij                           curves.Point
	Psi_ij                              curves.Scalar
	WitnessOfTheCommitmentToInstanceKey commitments.Witness
}

type Round2Broadcast struct {
	PK_i curves.Point
}

func (ic *Cosigner) Round1() (*Round1Broadcast, map[integration.IdentityKey]*Round1P2P, error) {
	if ic.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", ic.round)
	}
	// step 1.1
	ic.state.phi_i = ic.CohortConfig.CipherSuite.Curve.Scalar.Random(ic.prng)
	// step 1.2
	ic.state.r_i = ic.CohortConfig.CipherSuite.Curve.Scalar.Random(ic.prng)
	// step 1.3
	ic.state.R_i = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.r_i)

	outputP2P := make(map[integration.IdentityKey]*Round1P2P, len(ic.SessionParticipants))
	for _, participant := range ic.SessionParticipants {
		if participant.PublicKey().Equal(ic.MyIdentityKey.PublicKey()) {
			continue
		}

		// step 1.3.1
		message := prepareCommitmentMessage(ic.MyShamirId, ic.IdentityKeyToShamirId[participant], ic.UniqueSessionId, ic.state.R_i.ToAffineCompressed())
		commitmentToInstanceKey, witness, err := commitments.Commit(h, message)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not commit to instance key")
		}
		ic.state.witnessesOfCommitmentToInstanceKey[participant] = witness

		// step 1.3.2
		multiplicationOutput, err := ic.subprotocols.multiplication[participant].Bob.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "multiplication round 1")
		}

		// step 1.3.3
		ic.state.Chi_i[participant] = ic.subprotocols.multiplication[participant].Bob.BTilde[0] // this is effectively bob's input to the multiplication protocol
		if ic.subprotocols.multiplication[participant].Bob.BTilde[0].Cmp(ic.subprotocols.multiplication[participant].Bob.BTilde[1]) != 0 {
			return nil, nil, errs.WrapFailed(err, "bob's input is not compatible with forced reuse")
		}

		// step 1.3.4
		outputP2P[participant] = &Round1P2P{
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

func (ic *Cosigner) Round2(round1outputBroadcast map[integration.IdentityKey]*Round1Broadcast, round1outputP2P map[integration.IdentityKey]*Round1P2P) (*Round2Broadcast, map[integration.IdentityKey]*Round2P2P, error) {
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

	outputP2P := make(map[integration.IdentityKey]*Round2P2P)
	for _, participant := range ic.SessionParticipants {
		if participant.PublicKey().Equal(ic.MyIdentityKey.PublicKey()) {
			continue
		}
		// step 2.6.1
		receivedBroadcastMessage := round1outputBroadcast[participant]
		ic.state.receivedR_i[participant] = receivedBroadcastMessage.R_i

		// step 2.6.2
		receivedP2PMessage := round1outputP2P[participant]
		ic.state.receivedCommitmentsToInstanceKey[participant] = receivedP2PMessage.CommitmentToInstanceKey

		// step 2.6.3
		c_ij, multiplicationOutput, err := ic.subprotocols.multiplication[participant].Alice.Round2(receivedP2PMessage.MultiplicationOutput, a)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "F_RVOLE round 2 sample")
		}
		ic.state.cU_i[participant] = c_ij[0]
		ic.state.cV_i[participant] = c_ij[1]

		// step 2.6.4
		gammaU_ij := ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.cU_i[participant])
		// step 2.6.5
		gammaV_ij := ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.cV_i[participant])
		// step 2.6.6
		psi_ij := ic.state.phi_i.Sub(ic.state.Chi_i[participant])

		// step 2.6.7
		outputP2P[participant] = &Round2P2P{
			Multiplication:                      multiplicationOutput,
			GammaU_ij:                           gammaU_ij,
			GammaV_ij:                           gammaV_ij,
			Psi_ij:                              psi_ij,
			WitnessOfTheCommitmentToInstanceKey: ic.state.witnessesOfCommitmentToInstanceKey[participant],
		}
	}
	ic.round++
	// step 2.7
	return &Round2Broadcast{
		PK_i: ic.state.pk_i,
	}, outputP2P, nil
}

func (ic *Cosigner) Round3(round2outputBroadcast map[integration.IdentityKey]*Round2Broadcast, round2outputP2P map[integration.IdentityKey]*Round2P2P, message []byte) (*dkls23.PartialSignature, error) {
	if ic.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", ic.round)
	}
	refreshedPublicKey := ic.state.pk_i // this has zeta_i added so different than the one from public key share map
	R := ic.state.R_i
	phiPsi := ic.state.phi_i
	cUdU := ic.CohortConfig.CipherSuite.Curve.Scalar.Zero()
	cVdV := ic.CohortConfig.CipherSuite.Curve.Scalar.Zero()

	for _, participant := range ic.SessionParticipants {
		if participant.PublicKey().Equal(ic.MyIdentityKey.PublicKey()) {
			continue
		}
		// step 3.1.1
		receivedBroadcastedMessage, exists := round2outputBroadcast[participant]
		if !exists {
			return nil, errs.NewMissing("don't have broadcast message")
		}
		pk_j := receivedBroadcastedMessage.PK_i

		// step 3.1.2
		receivedP2PMessage, exists := round2outputP2P[participant]
		if !exists {
			return nil, errs.NewMissing("don't have p2p message")
		}
		GammaU_ji := receivedP2PMessage.GammaU_ij
		GammaV_ji := receivedP2PMessage.GammaV_ij

		// step 3.1.3
		supposedlyCommittedMessage := prepareCommitmentMessage(ic.IdentityKeyToShamirId[participant], ic.MyShamirId, ic.UniqueSessionId, ic.state.receivedR_i[participant].ToAffineCompressed())
		if err := commitments.Open(
			h,
			supposedlyCommittedMessage,
			ic.state.receivedCommitmentsToInstanceKey[participant],
			receivedP2PMessage.WitnessOfTheCommitmentToInstanceKey,
		); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "message could not be openned")
		}

		// step 3.1.4
		d_ij, err := ic.subprotocols.multiplication[participant].Bob.Round3(receivedP2PMessage.Multiplication)
		if err != nil {
			return nil, errs.WrapFailed(err, "bob round 3")
		}
		du_ij := d_ij[0]
		dv_ij := d_ij[1]

		Chi_ij := ic.state.Chi_i[participant]
		// step 3.1.5
		R_j := ic.state.receivedR_i[participant]
		lhs1 := R_j.Mul(Chi_ij).Sub(GammaU_ji)
		rhs1 := ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(du_ij)
		if !lhs1.Equal(rhs1) {
			return nil, errs.NewIdentifiableAbort("failed first check")
		}

		// step 3.1.6
		P_j := pk_j
		llhs := P_j.Mul(Chi_ij)
		lhs2 := llhs.Sub(GammaV_ji)
		rhs := ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(dv_ij)
		if !lhs2.Equal(rhs) {
			return nil, errs.NewIdentifiableAbort("failed second check")
		}

		refreshedPublicKey = refreshedPublicKey.Add(pk_j)
		// We're partially evaluating what we need for future steps inside of this loop
		cu_ij := ic.state.cU_i[participant]
		cv_ij := ic.state.cV_i[participant]
		phiPsi = phiPsi.Add(round2outputP2P[participant].Psi_ij)
		cUdU = cUdU.Add(cu_ij).Add(du_ij)
		cVdV = cVdV.Add(cv_ij).Add(dv_ij)
		R = R.Add(R_j) // step 3.3
	}

	// step 3.2
	if !refreshedPublicKey.Equal(ic.Shard.SigningKeyShare.PublicKey) {
		return nil, errs.NewFailed("recomputed public key is wrong")
	}

	// step 3.4
	u_i := ic.state.r_i.Mul(phiPsi).Add(cUdU)
	// step 3.5
	v_i := ic.state.sk_i.Mul(phiPsi).Add(cVdV)

	// step 3.6
	xBigInt := getXCoordinate(R)
	rx, err := ic.CohortConfig.CipherSuite.Curve.Scalar.SetBigInt(xBigInt)
	if err != nil {
		return nil, errs.WrapFailed(err, "rx")
	}
	// TODO: FiatShamir is not the right name. Clean up hash to curve scalar stuff. Alternative is regular hash then
	// setbytefunc
	digest, err := hashing.FiatShamir(ic.CohortConfig.CipherSuite, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce digest")
	}
	w_i := digest.Mul(ic.state.phi_i).Add(rx.Mul(v_i))

	ic.round++
	// step 3.7
	return &dkls23.PartialSignature{
		Ui: u_i,
		Wi: w_i,
		Ri: ic.state.R_i,
	}, nil
}

// Aggregate computes the sum of partial signatures to get a valid signature. It also normalises the signature to the low-s form as well as attaches the recovery id to the final signature.
func Aggregate(cipherSuite *integration.CipherSuite, publicKey curves.Point, partialSignatures map[integration.IdentityKey]*dkls23.PartialSignature, message []byte) (*ecdsa.Signature, error) {
	curve := cipherSuite.Curve
	w := curve.Scalar.Zero()
	u := curve.Scalar.Zero()
	R := curve.Point.Identity()
	for _, partialSignature := range partialSignatures {
		w = w.Add(partialSignature.Wi)
		u = u.Add(partialSignature.Ui)
		R = R.Add(partialSignature.Ri)
	}
	xBigInt := getXCoordinate(R)

	// step 4.2
	rx, err := curve.Scalar.SetBigInt(xBigInt)
	if err != nil {
		return nil, errs.WrapFailed(err, "rx")
	}
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

func prepareCommitmentMessage(myShamirId, theOtherShamirId int, uniqueSessionId, R_i []byte) []byte {
	return bytes.Join(
		[][]byte{
			{
				byte(myShamirId),
				byte(theOtherShamirId),
			},
			uniqueSessionId,
			R_i,
		},
		[]byte(""),
	)
}

// TODO: remove when curve interface is extended.
func getXCoordinate(point curves.Point) (x *big.Int) {
	affine := point.ToAffineUncompressed()
	return new(big.Int).SetBytes(affine[1:33])
}
