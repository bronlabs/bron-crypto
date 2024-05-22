package interactive_signing

import (
	"bytes"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/signing"
)

func (pc *PrimaryCosigner) Round1() (r1out *Round1OutputP2P, err error) {
	// Validation
	if pc.Round != 1 {
		return nil, errs.NewRound("Running round %d but primary cosigner expected round %d", 1, pc.Round)
	}

	// step 1.1: k1 <-$ Zq     &    R1 <- k1 * G
	pc.state.k1, err = pc.Protocol.Curve().ScalarField().Random(pc.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot generate k1")
	}
	pc.state.bigR1 = pc.Protocol.Curve().ScalarBaseMult(pc.state.k1)

	// step 1.2: c1 <- Commit(sid || Q || R1)
	committer, err := hashcommitments.NewCommitter(pc.SessionId, pc.Prng, pc.myAuthKey.PublicKey().ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot instantiate committer")
	}
	bigR1Commitment, bigR1Opening, err := committer.Commit(pc.state.bigR1.ToAffineCompressed())
	if err != nil {
		return nil, errs.NewFailed("cannot commit to R")
	}

	pc.state.bigR1Opening = bigR1Opening

	pc.Round = 3
	// step 1.3: Send(c1) -> P_2
	return &Round1OutputP2P{
		BigR1Commitment: bigR1Commitment,
	}, nil
}

func (sc *SecondaryCosigner) Round2(r1out *Round1OutputP2P) (r2out *Round2OutputP2P, err error) {
	// Validation
	if sc.Round != 2 {
		return nil, errs.NewRound("Running round %d but secondary cosigner expected round %d", 2, sc.Round)
	}
	if err := r1out.Validate(sc.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", sc.Round)
	}

	sc.state.bigR1Commitment = r1out.BigR1Commitment
	// step 2.1: k2 <-$ Zq     &    R2 <- k2 * G
	sc.state.k2, err = sc.Protocol.Curve().ScalarField().Random(sc.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot generate k2")
	}
	sc.state.bigR2 = sc.Protocol.Curve().ScalarBaseMult(sc.state.k2)
	// step 2.2: π <- NIPoK.Prove(k2)
	bigR2ProofSessionId, err := hashing.HashChain(base.RandomOracleHashFunction, sc.SessionId, sc.IdentityKey().PublicKey().ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce bigR2ProofSessionId")
	}
	sc.Transcript.AppendMessages("bigR2Proof", bigR2ProofSessionId)
	bigR2Proof, bigR2ProofStatement, err := dlog.Prove(bigR2ProofSessionId, sc.state.k2, sc.Protocol.Curve().Generator(), sc.nic, sc.Transcript.Clone(), sc.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not prove dlog")
	}
	if !sc.state.bigR2.Equal(bigR2ProofStatement) {
		return nil, errs.NewFailed("invalid statement, something went terribly wrong")
	}

	sc.Round = 4
	// step 2.3: Send(R2, π) -> P_1
	return &Round2OutputP2P{
		BigR2:      sc.state.bigR2,
		BigR2Proof: bigR2Proof,
	}, nil
}

func (pc *PrimaryCosigner) Round3(r2out *Round2OutputP2P) (r3out *Round3OutputP2P, err error) {
	// Validation
	if pc.Round != 3 {
		return nil, errs.NewRound("Running round %d but primary cosigner expected round %d", 3, pc.Round)
	}
	if err := r2out.Validate(pc.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", pc.Round)
	}

	bigR2ProofSessionId, err := hashing.HashChain(base.RandomOracleHashFunction, pc.SessionId, pc.secondaryIdentityKey.PublicKey().ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce bigR2ProofSessionId")
	}
	pc.Transcript.AppendMessages("bigR2Proof", bigR2ProofSessionId)
	if err := dlog.Verify(bigR2ProofSessionId, r2out.BigR2Proof, r2out.BigR2, pc.Protocol.Curve().Generator(), pc.nic, pc.Transcript.Clone()); err != nil {
		return nil, errs.WrapIdentifiableAbort(err, pc.secondaryIdentityKey.String(), "cannot verify R2 dlog proof")
	}

	bigR1ProofSessionId, err := hashing.HashChain(base.RandomOracleHashFunction, pc.SessionId, pc.myAuthKey.PublicKey().ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce bigR1ProofSessionId")
	}
	pc.Transcript.AppendMessages("bigR1Proof", bigR1ProofSessionId)
	bigR1Proof, bigR1ProofStatement, err := dlog.Prove(bigR1ProofSessionId, pc.state.k1, pc.Protocol.Curve().Generator(), pc.nic, pc.Transcript.Clone(), pc.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create R1 dlog proof")
	}
	if !pc.state.bigR1.Equal(bigR1ProofStatement) {
		return nil, errs.NewFailed("invalid R1 proof statement, something went terribly wrong")
	}

	pc.state.bigR = r2out.BigR2.ScalarMul(pc.state.k1)
	bigRx := pc.state.bigR.AffineX().Nat()
	pc.state.r = pc.Protocol.Curve().ScalarField().Element().SetNat(bigRx)

	pc.Round = 5
	return &Round3OutputP2P{
		BigR1Opening: pc.state.bigR1Opening,
		BigR1:        pc.state.bigR1,
		BigR1Proof:   bigR1Proof,
	}, nil
}

func (sc *SecondaryCosigner) Round4(r3out *Round3OutputP2P, message []byte) (round4Output *lindell17.PartialSignature, err error) {
	// Validation
	if sc.Round != 4 {
		return nil, errs.NewRound("Running round %d but secondary cosigner expected round %d", 4, sc.Round)
	}
	if err := r3out.Validate(sc.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", sc.Round)
	}

	verifier := hashcommitments.NewVerifier(sc.SessionId, sc.primaryIdentityKey.PublicKey().ToAffineCompressed())
	if !bytes.Equal(r3out.BigR1.ToAffineCompressed(), r3out.BigR1Opening.Message()) {
		return nil, errs.NewVerification("opening is not tied to the expected value")
	}
	if err := verifier.Verify(sc.state.bigR1Commitment, r3out.BigR1Opening); err != nil {
		return nil, errs.WrapFailed(err, "cannot open R commitment")
	}

	bigR1ProofSessionId, err := hashing.HashChain(base.RandomOracleHashFunction, sc.SessionId, sc.primaryIdentityKey.PublicKey().ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce bigR1ProofSessionId")
	}
	sc.Transcript.AppendMessages("bigR1Proof", bigR1ProofSessionId)
	if err := dlog.Verify(bigR1ProofSessionId, r3out.BigR1Proof, r3out.BigR1, sc.Protocol.Curve().Generator(), sc.nic, sc.Transcript.Clone()); err != nil {
		return nil, errs.WrapIdentifiableAbort(err, sc.primaryIdentityKey.String(), "cannot verify R1 dlog proof")
	}

	bigR := r3out.BigR1.ScalarMul(sc.state.k2)
	bigRx := bigR.AffineX().Nat()
	r := sc.Protocol.Curve().ScalarField().Element().SetNat(bigRx)

	k2 := sc.state.k2
	additiveShare, err := sc.myShard.SigningKeyShare.ToAdditive(sc.IdentityKey(), hashset.NewHashableHashSet(sc.IdentityKey(), sc.primaryIdentityKey), sc.Protocol)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive my additive share")
	}
	paillierPublicKey, exists := sc.myShard.PaillierPublicKeys.Get(sc.primaryIdentityKey)
	if !exists {
		return nil, errs.NewMissing("couldn't get primary paillier public key")
	}
	cKey, exists := sc.myShard.PaillierEncryptedShares.Get(sc.primaryIdentityKey)
	if !exists {
		return nil, errs.NewMissing("couldn't get primary encrypted signing key share")
	}
	primaryLagrangeCoefficient, err := signing.CalcOtherPartyLagrangeCoefficient((sc.primarySharingId), sc.mySharingId, sc.Protocol.TotalParties(), sc.Protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate Lagrange coefficients")
	}
	q := sc.Protocol.Curve().Order()
	mPrime, err := signing.MessageToScalar(sc.Protocol.SigningSuite(), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get scalar from message")
	}

	// c3 = Enc(ρq + k2^(-1)(m' + r * (y1 * λ1 + y2 * λ2)))
	c3, err := signing.CalcC3(primaryLagrangeCoefficient, k2, mPrime, r, additiveShare, q.Nat(), paillierPublicKey, cKey, sc.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate c3")
	}

	sc.Round++
	return &lindell17.PartialSignature{
		C3: c3,
	}, nil
}

func (pc *PrimaryCosigner) Round5(r4out *lindell17.PartialSignature, message []byte) (signature *ecdsa.Signature, err error) {
	// Validation
	if pc.Round != 5 {
		return nil, errs.NewRound("Running round %d but primary cosigner expected round %d", 5, pc.Round)
	}
	if err := r4out.Validate(pc.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", pc.Round)
	}

	paillierSecretKey := pc.myShard.PaillierSecretKey
	decryptor, err := paillier.NewDecryptor(paillierSecretKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create paillier decryptor")
	}
	sPrimeInt, err := decryptor.Decrypt(r4out.C3)
	if err != nil {
		return nil, errs.WrapIdentifiableAbort(err, pc.secondaryIdentityKey.String(), "cannot decrypt c3")
	}
	sPrime := pc.Protocol.Curve().ScalarField().Element().SetNat(sPrimeInt)
	k1Inv, err := pc.state.k1.MultiplicativeInverse()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute k1 inverse")
	}
	sDoublePrime := k1Inv.Mul(sPrime)

	v := new(int)
	*v, err = ecdsa.CalculateRecoveryId(pc.state.bigR)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute recovery id")
	}

	signature = &ecdsa.Signature{
		V: v,
		R: pc.state.r,
		S: sDoublePrime,
	}
	signature.Normalise()
	if err := ecdsa.Verify(signature, pc.Protocol.SigningSuite().Hash(), pc.myShard.SigningKeyShare.PublicKey, message); err != nil {
		return nil, errs.WrapIdentifiableAbort(err, pc.secondaryIdentityKey.String(), "could not verify produced signature")
	}
	pc.Round++
	return signature, nil
}
