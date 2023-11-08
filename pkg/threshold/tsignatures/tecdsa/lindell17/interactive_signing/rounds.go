package interactive_signing

import (
	"crypto/sha256"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	dlog "github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

type Round1OutputP2P struct {
	BigR1Commitment commitments.Commitment

	_ types.Incomparable
}

type Round2OutputP2P struct {
	BigR2      curves.Point
	BigR2Proof *dlog.Proof

	_ types.Incomparable
}

type Round3OutputP2P struct {
	BigR1Witness commitments.Witness
	BigR1        curves.Point
	BigR1Proof   *dlog.Proof

	_ types.Incomparable
}

type Round4OutputP2P struct {
	C3 *paillier.CipherText

	_ types.Incomparable
}

var commitmentHashFunc = sha256.New

func (primaryCosigner *PrimaryCosigner) Round1() (round1Output *Round1OutputP2P, err error) {
	if primaryCosigner.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", primaryCosigner.round)
	}

	primaryCosigner.state.k1, err = primaryCosigner.cohortConfig.CipherSuite.Curve.Scalar().Random(primaryCosigner.prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "cannot generate k1")
	}
	primaryCosigner.state.bigR1 = primaryCosigner.cohortConfig.CipherSuite.Curve.ScalarBaseMult(primaryCosigner.state.k1)

	bigR1CommitmentMessage := append(
		append(primaryCosigner.sessionId,
			primaryCosigner.myIdentityKey.PublicKey().ToAffineCompressed()...),
		primaryCosigner.state.bigR1.ToAffineCompressed()...,
	)
	bigR1Commitment, bigR1Witness, err := commitments.Commit(commitmentHashFunc, bigR1CommitmentMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to R1")
	}

	primaryCosigner.state.bigR1Witness = bigR1Witness

	primaryCosigner.round++
	return &Round1OutputP2P{
		BigR1Commitment: bigR1Commitment,
	}, nil
}

func (secondaryCosigner *SecondaryCosigner) Round2(round1Output *Round1OutputP2P) (round2Output *Round2OutputP2P, err error) {
	if secondaryCosigner.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", secondaryCosigner.round)
	}

	secondaryCosigner.state.bigR1Commitment = round1Output.BigR1Commitment

	secondaryCosigner.state.k2, err = secondaryCosigner.cohortConfig.CipherSuite.Curve.Scalar().Random(secondaryCosigner.prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "cannot generate k2")
	}
	secondaryCosigner.state.bigR2 = secondaryCosigner.cohortConfig.CipherSuite.Curve.ScalarBaseMult(secondaryCosigner.state.k2)

	bigR2ProofSessionId := append(secondaryCosigner.sessionId, secondaryCosigner.myIdentityKey.PublicKey().ToAffineCompressed()...)
	secondaryCosigner.transcript.AppendMessages("bigR2Proof", bigR2ProofSessionId)
	bigR2Prover, err := dlog.NewProver(secondaryCosigner.cohortConfig.CipherSuite.Curve.Generator(), bigR2ProofSessionId, secondaryCosigner.transcript.Clone(), secondaryCosigner.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog prover")
	}
	bigR2Proof, bigR2ProofStatement, err := bigR2Prover.Prove(secondaryCosigner.state.k2)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create R2 dlog proof")
	}
	if !secondaryCosigner.state.bigR2.Equal(bigR2ProofStatement) {
		return nil, errs.NewFailed("invalid statement, something went terribly wrong")
	}

	secondaryCosigner.round++
	return &Round2OutputP2P{
		BigR2:      secondaryCosigner.state.bigR2,
		BigR2Proof: bigR2Proof,
	}, nil
}

func (primaryCosigner *PrimaryCosigner) Round3(round2Output *Round2OutputP2P) (round3Output *Round3OutputP2P, err error) {
	if primaryCosigner.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", primaryCosigner.round)
	}

	bigR2ProofSessionId := append(primaryCosigner.sessionId, primaryCosigner.secondaryIdentityKey.PublicKey().ToAffineCompressed()...)
	primaryCosigner.transcript.AppendMessages("bigR2Proof", bigR2ProofSessionId)
	err = dlog.Verify(primaryCosigner.cohortConfig.CipherSuite.Curve.Generator(), round2Output.BigR2, round2Output.BigR2Proof, bigR2ProofSessionId)
	if err != nil {
		return nil, errs.WrapTotalAbort(err, "secondary", "cannot verify R2 dlog proof")
	}

	bigR1ProofSessionId := append(primaryCosigner.sessionId, primaryCosigner.myIdentityKey.PublicKey().ToAffineCompressed()...)
	primaryCosigner.transcript.AppendMessages("bigR1Proof", bigR1ProofSessionId)
	bigR1Prover, err := dlog.NewProver(primaryCosigner.cohortConfig.CipherSuite.Curve.Generator(), bigR1ProofSessionId, primaryCosigner.transcript.Clone(), primaryCosigner.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog prover")
	}
	bigR1Proof, bigR1ProofStatement, err := bigR1Prover.Prove(primaryCosigner.state.k1)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create R1 dlog proof")
	}
	if !primaryCosigner.state.bigR1.Equal(bigR1ProofStatement) {
		return nil, errs.NewFailed("invalid R1 proof statement, something went terribly wrong")
	}

	primaryCosigner.state.bigR = round2Output.BigR2.Mul(primaryCosigner.state.k1)
	bigRx := primaryCosigner.state.bigR.X().Nat()
	primaryCosigner.state.r, err = primaryCosigner.cohortConfig.CipherSuite.Curve.Scalar().SetNat(bigRx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get R.x")
	}

	primaryCosigner.round++
	return &Round3OutputP2P{
		BigR1Witness: primaryCosigner.state.bigR1Witness,
		BigR1:        primaryCosigner.state.bigR1,
		BigR1Proof:   bigR1Proof,
	}, nil
}

func (secondaryCosigner *SecondaryCosigner) Round4(round3Output *Round3OutputP2P, message []byte) (round4Output *Round4OutputP2P, err error) {
	if secondaryCosigner.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", secondaryCosigner.round)
	}

	bigR1CommitmentMessage := append(append(secondaryCosigner.sessionId, secondaryCosigner.primaryIdentityKey.PublicKey().ToAffineCompressed()...), round3Output.BigR1.ToAffineCompressed()...)
	err = commitments.Open(commitmentHashFunc, bigR1CommitmentMessage, secondaryCosigner.state.bigR1Commitment, round3Output.BigR1Witness)
	if err != nil {
		return nil, errs.WrapTotalAbort(err, "primary", "cannot open R1 commitment")
	}

	bigR1ProofSessionId := append(secondaryCosigner.sessionId, secondaryCosigner.primaryIdentityKey.PublicKey().ToAffineCompressed()...)
	secondaryCosigner.transcript.AppendMessages("bigR1Proof", bigR1ProofSessionId)
	if err := dlog.Verify(secondaryCosigner.cohortConfig.CipherSuite.Curve.Point().Generator(), round3Output.BigR1, round3Output.BigR1Proof, bigR1ProofSessionId); err != nil {
		return nil, errs.WrapTotalAbort(err, "primary", "cannot verify R1 dlog proof")
	}

	bigR := round3Output.BigR1.Mul(secondaryCosigner.state.k2)
	bigRx := bigR.X().Nat()
	r, err := secondaryCosigner.cohortConfig.CipherSuite.Curve.Scalar().SetNat(bigRx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get R.x")
	}

	k2 := secondaryCosigner.state.k2
	shamirShare := &shamir.Share{
		Id:    secondaryCosigner.mySharingId,
		Value: secondaryCosigner.myShard.SigningKeyShare.Share,
	}
	additiveShare, err := shamirShare.ToAdditive([]int{secondaryCosigner.mySharingId, secondaryCosigner.primarySharingId})
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive my additive share")
	}
	paillierPublicKey := secondaryCosigner.myShard.PaillierPublicKeys[secondaryCosigner.primaryIdentityKey.Hash()]
	cKey := secondaryCosigner.myShard.PaillierEncryptedShares[secondaryCosigner.primaryIdentityKey.Hash()]
	primaryLagrangeCoefficient, err := CalcOtherPartyLagrangeCoefficient(secondaryCosigner.primarySharingId, secondaryCosigner.mySharingId, secondaryCosigner.cohortConfig.Protocol.TotalParties, secondaryCosigner.cohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate Lagrange coefficients")
	}
	q := secondaryCosigner.cohortConfig.CipherSuite.Curve.Profile().SubGroupOrder()
	mPrime, err := MessageToScalar(secondaryCosigner.cohortConfig.CipherSuite.Hash, secondaryCosigner.cohortConfig.CipherSuite.Curve, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get scalar from message")
	}

	// c3 = Enc(ρq + k2^(-1)(m' + r * (y1 * λ1 + y2 * λ2)))
	c3, err := CalcC3(primaryLagrangeCoefficient, k2, mPrime, r, additiveShare, q.Nat(), paillierPublicKey, cKey, secondaryCosigner.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate c3")
	}

	secondaryCosigner.round++
	return &Round4OutputP2P{
		C3: c3,
	}, nil
}

func (primaryCosigner *PrimaryCosigner) Round5(round4Output *Round4OutputP2P, message []byte) (signature *ecdsa.Signature, err error) {
	if primaryCosigner.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", primaryCosigner.round)
	}

	paillierSecretKey := primaryCosigner.myShard.PaillierSecretKey
	decryptor, err := paillier.NewDecryptor(paillierSecretKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create paillier decryptor")
	}
	sPrimeInt, err := decryptor.Decrypt(round4Output.C3)
	if err != nil {
		return nil, errs.WrapTotalAbort(err, "secondary", "cannot decrypt c3")
	}
	sPrime, err := primaryCosigner.cohortConfig.CipherSuite.Curve.Scalar().SetNat(sPrimeInt)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar value")
	}

	k1Inv, err := primaryCosigner.state.k1.Invert()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot invert k1")
	}
	sDoublePrime := k1Inv.Mul(sPrime)

	v := new(int)
	*v, err = ecdsa.CalculateRecoveryId(primaryCosigner.state.bigR)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute recovery id")
	}

	signature = &ecdsa.Signature{
		V: v,
		R: primaryCosigner.state.r,
		S: sDoublePrime,
	}
	signature.Normalise()
	if err := ecdsa.Verify(signature, primaryCosigner.cohortConfig.CipherSuite.Hash, primaryCosigner.myShard.SigningKeyShare.PublicKey, message); err != nil {
		return nil, errs.WrapTotalAbort(err, "secondary", "could not verify produced signature")
	}
	return signature, nil
}
