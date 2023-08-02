package interactive

import (
	crand "crypto/rand"
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/hashing"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/shamir"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/ecdsa"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	dlog "github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"math/big"
)

type Round1OutputP2P struct {
	BigR1Commitment commitments.Commitment
}

type Round2OutputP2P struct {
	BigR2      curves.Point
	BigR2Proof *dlog.Proof
}

type Round3OutputP2P struct {
	BigR1Witness commitments.Witness
	BigR1        curves.Point
	BigR1Proof   *dlog.Proof
}

type Round4OutputP2P struct {
	C3 paillier.CipherText
}

var (
	commitmentHashFunc = sha256.New
)

func (primaryCosigner *PrimaryCosigner) Round1() (round1Output *Round1OutputP2P, err error) {
	if primaryCosigner.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", primaryCosigner.round)
	}

	primaryCosigner.state.k1 = primaryCosigner.cohortConfig.CipherSuite.Curve.NewScalar().Random(primaryCosigner.prng)
	primaryCosigner.state.bigR1 = primaryCosigner.cohortConfig.CipherSuite.Curve.ScalarBaseMult(primaryCosigner.state.k1)

	bigR1CommitmentMessage := append(append(primaryCosigner.sessionId[:], primaryCosigner.myIdentityKey.PublicKey().ToAffineCompressed()...), primaryCosigner.state.bigR1.ToAffineCompressed()...)
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

	secondaryCosigner.state.k2 = secondaryCosigner.cohortConfig.CipherSuite.Curve.NewScalar().Random(secondaryCosigner.prng)
	secondaryCosigner.state.bigR2 = secondaryCosigner.cohortConfig.CipherSuite.Curve.ScalarBaseMult(secondaryCosigner.state.k2)

	bigR2ProofSessionId := append(secondaryCosigner.sessionId[:], secondaryCosigner.myIdentityKey.PublicKey().ToAffineCompressed()...)
	bigR2Prover, err := dlog.NewProver(secondaryCosigner.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), bigR2ProofSessionId, secondaryCosigner.transcript.Clone())
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

	bigR2ProofSessionId := append(primaryCosigner.sessionId[:], primaryCosigner.secondaryIdentityKey.PublicKey().ToAffineCompressed()...)
	err = dlog.Verify(primaryCosigner.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), round2Output.BigR2, round2Output.BigR2Proof, bigR2ProofSessionId, primaryCosigner.transcript.Clone())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot verify R2 dlog proof")
	}

	bigR1ProofSessionId := append(primaryCosigner.sessionId[:], primaryCosigner.myIdentityKey.PublicKey().ToAffineCompressed()...)
	bigR1Prover, err := dlog.NewProver(primaryCosigner.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), bigR1ProofSessionId, nil)
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
	bigRx, _ := lindell17.GetPointCoordinates(primaryCosigner.state.bigR)
	primaryCosigner.state.r, err = primaryCosigner.cohortConfig.CipherSuite.Curve.Scalar.SetBigInt(bigRx)
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

	bigR1CommitmentMessage := append(append(secondaryCosigner.sessionId[:], secondaryCosigner.primaryIdentityKey.PublicKey().ToAffineCompressed()...), round3Output.BigR1.ToAffineCompressed()...)
	err = commitments.Open(commitmentHashFunc, bigR1CommitmentMessage, secondaryCosigner.state.bigR1Commitment, round3Output.BigR1Witness)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot open R1 commitment")
	}

	bigR1ProofSessionId := append(secondaryCosigner.sessionId[:], secondaryCosigner.primaryIdentityKey.PublicKey().ToAffineCompressed()...)
	if err := dlog.Verify(secondaryCosigner.cohortConfig.CipherSuite.Curve.Point.Generator(), round3Output.BigR1, round3Output.BigR1Proof, bigR1ProofSessionId, nil); err != nil { // TODO: clone transcript
		return nil, errs.WrapFailed(err, "cannot verify R1 dlog proof")
	}

	bigR := round3Output.BigR1.Mul(secondaryCosigner.state.k2)
	bigRx, _ := lindell17.GetPointCoordinates(bigR)
	r, err := secondaryCosigner.cohortConfig.CipherSuite.Curve.Scalar.SetBigInt(bigRx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get R.x")
	}

	messageHash, err := hashing.Hash(secondaryCosigner.cohortConfig.CipherSuite.Hash, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash message")
	}
	mPrimeInt, err := lindell17.HashToInt(messageHash, secondaryCosigner.cohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create int from hash")
	}
	mPrime, err := secondaryCosigner.cohortConfig.CipherSuite.Curve.NewScalar().SetBigInt(mPrimeInt)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash to scalar")
	}

	paillierPublicKey := secondaryCosigner.myShard.PaillierPublicKeys[secondaryCosigner.primaryIdentityKey]
	cKey := secondaryCosigner.myShard.PaillierEncryptedShares[secondaryCosigner.primaryIdentityKey]

	k2Inv, err := secondaryCosigner.state.k2.Invert()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot invert k2")
	}

	// c1 = Enc(ρq + k2^(-1) * m')
	c1Plain := k2Inv.Mul(mPrime).BigInt()
	q, err := lindell17.GetCurveOrder(secondaryCosigner.cohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get curve order")
	}
	qSquared := new(big.Int).Mul(q, q)
	rho, err := crand.Int(secondaryCosigner.prng, qSquared)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random int")
	}
	rhoMulQ := new(big.Int).Mul(rho, q)
	c1, _, err := paillierPublicKey.Encrypt(new(big.Int).Add(rhoMulQ, c1Plain))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt c1")
	}

	// c2 = Enc(k2^(-1) * r * (y1 * λ1 + y2 * λ2))
	dealer, err := shamir.NewDealer(secondaryCosigner.cohortConfig.Threshold, secondaryCosigner.cohortConfig.TotalParties, secondaryCosigner.cohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create shamir dealer")
	}
	coefficients, err := dealer.LagrangeCoefficients([]int{secondaryCosigner.primaryShamirId, secondaryCosigner.myShamirId})
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get Lagrange coefficients")
	}
	lambda1 := coefficients[secondaryCosigner.primaryShamirId]
	c2Left, err := paillierPublicKey.Mul(k2Inv.Mul(r).Mul(lambda1).BigInt(), cKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "homomorphic multiplication failed")
	}
	lambda2 := coefficients[secondaryCosigner.myShamirId]
	c2Right, _, err := paillierPublicKey.Encrypt(k2Inv.Mul(r).Mul(lambda2).Mul(secondaryCosigner.myShard.SigningKeyShare.Share).BigInt())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt c2")
	}
	c2, err := paillierPublicKey.Add(c2Left, c2Right)
	if err != nil {
		return nil, errs.WrapFailed(err, "homomorphic addition failed")
	}

	// c3 = c1 + c2 = Enc(ρq + k2^(-1)(m' + r * (y1 * λ1 + y2 * λ2)))
	c3, err := paillierPublicKey.Add(c1, c2)

	secondaryCosigner.round++
	return &Round4OutputP2P{
		c3,
	}, nil
}

func (primaryCosigner *PrimaryCosigner) Round5(round4Output *Round4OutputP2P, message []byte) (signatureExt *ecdsa.SignatureExt, err error) {
	if primaryCosigner.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", primaryCosigner.round)
	}

	paillierSecretKey := primaryCosigner.myShard.PaillierSecretKey
	sPrimeInt, err := paillierSecretKey.Decrypt(round4Output.C3)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decrypt c3")
	}
	sPrime, err := primaryCosigner.cohortConfig.CipherSuite.Curve.NewScalar().SetBigInt(sPrimeInt)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar value")
	}

	k1Inv, err := primaryCosigner.state.k1.Invert()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot invert k1")
	}
	sDoublePrime := k1Inv.Mul(sPrime)

	publicKey := &ecdsa.PublicKey{
		Q: primaryCosigner.myShard.SigningKeyShare.PublicKey,
	}

	signature := &ecdsa.Signature{
		R: primaryCosigner.state.r,
		S: sDoublePrime,
	}
	signature.Normalize()
	if ok := signature.VerifyMessageWithPublicKey(publicKey, primaryCosigner.cohortConfig.CipherSuite.Hash, message); !ok {
		return nil, errs.NewFailed("invalid signature")
	}

	recoveryId, err := ecdsa.CalculateRecoveryId(primaryCosigner.state.bigR)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate recovery id")
	}
	if ok := signature.VerifyMessageWithRecoveryId(recoveryId, primaryCosigner.cohortConfig.CipherSuite.Hash, message); !ok {
		return nil, errs.NewFailed("invalid recovery id")
	}

	primaryCosigner.round++
	return &ecdsa.SignatureExt{
		Signature:  *signature,
		RecoveryId: *recoveryId,
	}, nil
}
