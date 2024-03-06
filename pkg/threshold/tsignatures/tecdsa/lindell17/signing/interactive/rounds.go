package interactive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/signing"
)

func (primaryCosigner *PrimaryCosigner) Round1() (round1Output *Round1OutputP2P, err error) {
	// Validation
	if err := primaryCosigner.InRound(1); err != nil {
		return nil, errs.Forward(err)
	}

	// step 1.1: k1 <-$ Zq     &    R1 <- k1 * G
	primaryCosigner.state.k1, err = primaryCosigner.Protocol().Curve().ScalarField().Random(primaryCosigner.Prng())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot generate k1")
	}
	primaryCosigner.state.bigR1 = primaryCosigner.Protocol().Curve().ScalarBaseMult(primaryCosigner.state.k1)

	// step 1.2: c1 <- Commit(sid || Q || R1)
	bigR1Commitment, bigR1Witness, err := commitments.Commit(
		primaryCosigner.SessionId(),
		primaryCosigner.Prng(),
		primaryCosigner.myAuthKey.PublicKey().ToAffineCompressed(),
		primaryCosigner.state.bigR1.ToAffineCompressed(),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to R1")
	}

	primaryCosigner.state.bigR1Witness = bigR1Witness

	primaryCosigner.NextRound(3)
	// step 1.3: Send(c1) -> P_2
	return &Round1OutputP2P{
		BigR1Commitment: bigR1Commitment,
	}, nil
}

func (secondaryCosigner *SecondaryCosigner) Round2(round1Output *Round1OutputP2P) (round2Output *Round2OutputP2P, err error) {
	// Validation
	if err := secondaryCosigner.InRound(2); err != nil {
		return nil, errs.Forward(err)
	}
	if err := network.ValidateMessage(round1Output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 1 output")
	}

	secondaryCosigner.state.bigR1Commitment = round1Output.BigR1Commitment
	// step 2.1: k2 <-$ Zq     &    R2 <- k2 * G
	secondaryCosigner.state.k2, err = secondaryCosigner.Protocol().Curve().ScalarField().Random(secondaryCosigner.Prng())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot generate k2")
	}
	secondaryCosigner.state.bigR2 = secondaryCosigner.Protocol().Curve().ScalarBaseMult(secondaryCosigner.state.k2)
	// step 2.2: π <- NIPoK.Prove(k2)
	bigR2ProofSessionId, err := hashing.HashChain(base.RandomOracleHashFunction, secondaryCosigner.SessionId(), secondaryCosigner.IdentityKey().PublicKey().ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce bigR2ProofSessionId")
	}
	secondaryCosigner.Transcript().AppendMessages("bigR2Proof", bigR2ProofSessionId)
	bigR2Proof, bigR2ProofStatement, err := dlog.Prove(bigR2ProofSessionId, secondaryCosigner.state.k2, secondaryCosigner.Protocol().Curve().Generator(), secondaryCosigner.nic, secondaryCosigner.Transcript().Clone(), secondaryCosigner.Prng())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not prove dlog")
	}
	if !secondaryCosigner.state.bigR2.Equal(bigR2ProofStatement) {
		return nil, errs.NewFailed("invalid statement, something went terribly wrong")
	}

	secondaryCosigner.NextRound(4)
	// step 2.3: Send(R2, π) -> P_1
	return &Round2OutputP2P{
		BigR2:      secondaryCosigner.state.bigR2,
		BigR2Proof: bigR2Proof,
	}, nil
}

func (primaryCosigner *PrimaryCosigner) Round3(round2Output *Round2OutputP2P) (round3Output *Round3OutputP2P, err error) {
	// Validation
	if err := primaryCosigner.InRound(3); err != nil {
		return nil, errs.Forward(err)
	}
	if err := network.ValidateMessage(round2Output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 output")
	}

	bigR2ProofSessionId, err := hashing.HashChain(base.RandomOracleHashFunction, primaryCosigner.SessionId(), primaryCosigner.secondaryIdentityKey.PublicKey().ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce bigR2ProofSessionId")
	}
	primaryCosigner.Transcript().AppendMessages("bigR2Proof", bigR2ProofSessionId)
	if err := dlog.Verify(bigR2ProofSessionId, round2Output.BigR2Proof, round2Output.BigR2, primaryCosigner.Protocol().Curve().Generator(), primaryCosigner.nic, primaryCosigner.Transcript().Clone()); err != nil {
		return nil, errs.WrapTotalAbort(err, "secondary", "cannot verify R2 dlog proof")
	}

	bigR1ProofSessionId, err := hashing.HashChain(base.RandomOracleHashFunction, primaryCosigner.SessionId(), primaryCosigner.myAuthKey.PublicKey().ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce bigR1ProofSessionId")
	}
	primaryCosigner.Transcript().AppendMessages("bigR1Proof", bigR1ProofSessionId)
	bigR1Proof, bigR1ProofStatement, err := dlog.Prove(bigR1ProofSessionId, primaryCosigner.state.k1, primaryCosigner.Protocol().Curve().Generator(), primaryCosigner.nic, primaryCosigner.Transcript().Clone(), primaryCosigner.Prng())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create R1 dlog proof")
	}
	if !primaryCosigner.state.bigR1.Equal(bigR1ProofStatement) {
		return nil, errs.NewFailed("invalid R1 proof statement, something went terribly wrong")
	}

	primaryCosigner.state.bigR = round2Output.BigR2.Mul(primaryCosigner.state.k1)
	bigRx := primaryCosigner.state.bigR.AffineX().Nat()
	primaryCosigner.state.r = primaryCosigner.Protocol().Curve().Scalar().SetNat(bigRx)

	primaryCosigner.NextRound(5)
	return &Round3OutputP2P{
		BigR1Witness: primaryCosigner.state.bigR1Witness,
		BigR1:        primaryCosigner.state.bigR1,
		BigR1Proof:   bigR1Proof,
	}, nil
}

func (secondaryCosigner *SecondaryCosigner) Round4(round3Output *Round3OutputP2P, message []byte) (round4Output *lindell17.PartialSignature, err error) {
	// Validation
	if err := secondaryCosigner.InRound(4); err != nil {
		return nil, errs.Forward(err)
	}
	if err := network.ValidateMessage(round3Output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 3 output")
	}

	err = commitments.Open(secondaryCosigner.SessionId(), secondaryCosigner.state.bigR1Commitment, round3Output.BigR1Witness, secondaryCosigner.primaryIdentityKey.PublicKey().ToAffineCompressed(), round3Output.BigR1.ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapTotalAbort(err, "primary", "cannot open R1 commitment")
	}

	bigR1ProofSessionId, err := hashing.HashChain(base.RandomOracleHashFunction, secondaryCosigner.SessionId(), secondaryCosigner.primaryIdentityKey.PublicKey().ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce bigR1ProofSessionId")
	}
	secondaryCosigner.Transcript().AppendMessages("bigR1Proof", bigR1ProofSessionId)
	if err := dlog.Verify(bigR1ProofSessionId, round3Output.BigR1Proof, round3Output.BigR1, secondaryCosigner.Protocol().Curve().Generator(), secondaryCosigner.nic, secondaryCosigner.Transcript().Clone()); err != nil {
		return nil, errs.WrapTotalAbort(err, "primary", "cannot verify R1 dlog proof")
	}

	bigR := round3Output.BigR1.Mul(secondaryCosigner.state.k2)
	bigRx := bigR.AffineX().Nat()
	r := secondaryCosigner.Protocol().Curve().Scalar().SetNat(bigRx)

	k2 := secondaryCosigner.state.k2
	additiveShare, err := secondaryCosigner.myShard.SigningKeyShare.ToAdditive(secondaryCosigner.IdentityKey(), hashset.NewHashableHashSet(secondaryCosigner.IdentityKey(), secondaryCosigner.primaryIdentityKey), secondaryCosigner.Protocol())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive my additive share")
	}
	paillierPublicKey, exists := secondaryCosigner.myShard.PaillierPublicKeys.Get(secondaryCosigner.primaryIdentityKey)
	if !exists {
		return nil, errs.NewMissing("couldn't get primary paillier public key")
	}
	cKey, exists := secondaryCosigner.myShard.PaillierEncryptedShares.Get(secondaryCosigner.primaryIdentityKey)
	if !exists {
		return nil, errs.NewMissing("couldn't get primary encrypted signing key share")
	}
	primaryLagrangeCoefficient, err := signing.CalcOtherPartyLagrangeCoefficient((secondaryCosigner.primarySharingId), secondaryCosigner.mySharingId, secondaryCosigner.Protocol().TotalParties(), secondaryCosigner.Protocol().Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate Lagrange coefficients")
	}
	q := secondaryCosigner.Protocol().Curve().SubGroupOrder()
	mPrime, err := signing.MessageToScalar(secondaryCosigner.Protocol().CipherSuite(), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get scalar from message")
	}

	// c3 = Enc(ρq + k2^(-1)(m' + r * (y1 * λ1 + y2 * λ2)))
	c3, err := signing.CalcC3(primaryLagrangeCoefficient, k2, mPrime, r, additiveShare, q.Nat(), paillierPublicKey, cKey, secondaryCosigner.Prng())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate c3")
	}

	secondaryCosigner.LastRound()
	return &lindell17.PartialSignature{
		C3: c3,
	}, nil
}

func (primaryCosigner *PrimaryCosigner) Round5(round4Output *lindell17.PartialSignature, message []byte) (signature *ecdsa.Signature, err error) {
	// Validation
	if err := primaryCosigner.InRound(5); err != nil {
		return nil, errs.Forward(err)
	}
	if err := network.ValidateMessage(round4Output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 4 output")
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
	sPrime := primaryCosigner.Protocol().Curve().Scalar().SetNat(sPrimeInt)
	k1Inv := primaryCosigner.state.k1.MultiplicativeInverse()
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
	if err := ecdsa.Verify(signature, primaryCosigner.Protocol().CipherSuite().Hash(), primaryCosigner.myShard.SigningKeyShare.PublicKey, message); err != nil {
		return nil, errs.WrapTotalAbort(err, "secondary", "could not verify produced signature")
	}
	primaryCosigner.LastRound()
	return signature, nil
}
