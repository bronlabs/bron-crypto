package interactive

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/hashing"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/shamir"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/ecdsa"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"math/big"
)

type PrimaryRound1Output struct {
	k1ProofCommitment commitments.Commitment
}

type PrimaryRound3Output struct {
	k1Proof        *schnorr.Proof
	k1ProofWitness commitments.Witness
}

type SecondaryRound2Output struct {
	k2Proof *schnorr.Proof
}

type SecondaryRound4Output struct {
	c3 paillier.CipherText
}

var (
	commitmentHashFunc = sha256.New
)

func (primaryCosigner *PrimaryCosigner) Round1() (primaryRound1Output *PrimaryRound1Output, err error) {
	if primaryCosigner.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", primaryCosigner.round)
	}

	primaryCosigner.state.k1 = primaryCosigner.cohortConfig.CipherSuite.Curve.NewScalar().Random(primaryCosigner.prng)

	proverSessionId := append(primaryCosigner.sessionId[:], byte(primaryCosigner.myShamirId))
	prover1, err := schnorr.NewProver(primaryCosigner.cohortConfig.CipherSuite.Curve.Point.Generator(), proverSessionId, nil) // TODO: clone transcript
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Schnorr prover")
	}
	primaryCosigner.state.k1Proof, err = prover1.Prove(primaryCosigner.state.k1)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Schnorr proof")
	}

	k1ProofMessage, err := json.Marshal(primaryCosigner.state.k1Proof)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "cannot marshall k1 proof")
	}
	k1ProofCommitment, k1ProofWitness, err := commitments.Commit(commitmentHashFunc, k1ProofMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create k1 proof commitment")
	}
	primaryCosigner.state.k1ProofWitness = k1ProofWitness

	primaryCosigner.round++
	return &PrimaryRound1Output{
		k1ProofCommitment: k1ProofCommitment,
	}, nil
}

func (secondaryCosigner *SecondaryCosigner) Round2(primaryRound1Output *PrimaryRound1Output) (secondaryRound2Output *SecondaryRound2Output, err error) {
	if secondaryCosigner.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", secondaryCosigner.round)
	}

	secondaryCosigner.state.k1ProofCommitment = primaryRound1Output.k1ProofCommitment
	secondaryCosigner.state.k2 = secondaryCosigner.cohortConfig.CipherSuite.Curve.NewScalar().Random(secondaryCosigner.prng)
	proverSessionId := append(secondaryCosigner.sessionId[:], byte(secondaryCosigner.myShamirId))
	prover2, err := schnorr.NewProver(secondaryCosigner.cohortConfig.CipherSuite.Curve.Point.Generator(), proverSessionId, nil) // TODO: clone transcript
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Schnorr prover")
	}
	k2Proof, err := prover2.Prove(secondaryCosigner.state.k2)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Schnorr proof")
	}

	secondaryCosigner.round++
	return &SecondaryRound2Output{
		k2Proof: k2Proof,
	}, nil
}

func (primaryCosigner *PrimaryCosigner) Round3(secondaryRound2Output *SecondaryRound2Output) (primaryRound3Output *PrimaryRound3Output, err error) {
	if primaryCosigner.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", primaryCosigner.round)
	}

	proverSessionId := append(primaryCosigner.sessionId[:], byte(primaryCosigner.secondaryShamirId))
	err = schnorr.Verify(primaryCosigner.cohortConfig.CipherSuite.Curve.Point.Generator(), secondaryRound2Output.k2Proof, proverSessionId, nil) // TODO: clone transcript
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot verify Schnorr proof")
	}
	primaryCosigner.state.bigR = secondaryRound2Output.k2Proof.Statement.Mul(primaryCosigner.state.k1)
	bigRx, _ := lindell17.GetPointCoordinates(primaryCosigner.state.bigR)
	primaryCosigner.state.r, err = primaryCosigner.cohortConfig.CipherSuite.Curve.Scalar.SetBigInt(bigRx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get R.x")
	}

	primaryCosigner.round++
	return &PrimaryRound3Output{
		k1Proof:        primaryCosigner.state.k1Proof,
		k1ProofWitness: primaryCosigner.state.k1ProofWitness,
	}, nil
}

func (secondaryCosigner *SecondaryCosigner) Round4(primaryRound3Output *PrimaryRound3Output, message []byte) (secondaryRound4Output *SecondaryRound4Output, err error) {
	if secondaryCosigner.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", secondaryCosigner.round)
	}

	k1ProofMessage, err := json.Marshal(primaryRound3Output.k1Proof)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot marshal k1 proof")
	}
	if err := commitments.Open(commitmentHashFunc, k1ProofMessage, secondaryCosigner.state.k1ProofCommitment, primaryRound3Output.k1ProofWitness); err != nil {
		return nil, errs.WrapFailed(err, "cannot open commitment")
	}
	sessionId := append(secondaryCosigner.sessionId[:], byte(secondaryCosigner.primaryShamirId))
	if err := schnorr.Verify(secondaryCosigner.cohortConfig.CipherSuite.Curve.Point.Generator(), primaryRound3Output.k1Proof, sessionId, nil); err != nil { // TODO: clone transcript
		return nil, errs.WrapFailed(err, "cannot verify Schnorr proof")
	}
	bigR := primaryRound3Output.k1Proof.Statement.Mul(secondaryCosigner.state.k2)
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
	return &SecondaryRound4Output{
		c3,
	}, nil
}

func (primaryCosigner *PrimaryCosigner) Round5(secondaryRound4Output *SecondaryRound4Output, message []byte) (signatureExt *ecdsa.SignatureExt, err error) {
	if primaryCosigner.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", primaryCosigner.round)
	}

	paillierSecretKey := primaryCosigner.myShard.PaillierSecretKey
	sPrimeInt, err := paillierSecretKey.Decrypt(secondaryRound4Output.c3)
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
	sBis := k1Inv.Mul(sPrime)

	publicKey := &ecdsa.PublicKey{
		Q: primaryCosigner.myShard.SigningKeyShare.PublicKey,
	}

	signature := &ecdsa.Signature{
		R: primaryCosigner.state.r,
		S: sBis,
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
