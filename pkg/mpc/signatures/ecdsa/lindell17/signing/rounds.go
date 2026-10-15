package signing

import (
	"encoding/binary"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	transcriptDLogSLabel = "Lindell2017SignDLogS-"
	proverLabel          = "Lindell2017SignProver-"
)

// Round1 executes the primary cosigner's first round.
func (pc *PrimaryCosigner[P, B, S]) Round1() (r1out *Round1OutputP2P[P, B, S], err error) {
	// Validation
	if pc.round != 1 {
		return nil, ErrRound.WithMessage("Running round %d but primary cosigner expected round %d", 1, pc.round)
	}

	// step 1.1: k1 <-$ Zq     &    R1 <- k1 * G
	pc.state.k1, err = pc.suite.Curve().ScalarField().Random(pc.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate k1")
	}
	pc.state.bigR1 = pc.suite.Curve().ScalarBaseMul(pc.state.k1)
	// step 1.2: π1 <- NIPoK.Prove(k1)
	pc.state.bigR1Proof, err = dlogProve(&pc.Cosigner, pc.state.k1, pc.state.bigR1, pc.secondarySharingID)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create R1 dlog proof")
	}
	// step 1.3: c1 <- Commit(R1, π1)
	commitmentMessage := bigR1CommitmentMessage(pc.state.bigR1, pc.state.bigR1Proof)
	bigR1Commitment, bigR1Opening, err := commitments.Commit(pc.commitmentKey, commitmentMessage, pc.prng)
	if err != nil {
		return nil, ErrFailed.WithMessage("cannot commit to R")
	}

	pc.state.bigR1Opening = bigR1Opening

	pc.round += 2
	// step 1.4: Send(c1) -> P_2
	return &Round1OutputP2P[P, B, S]{
		BigR1Commitment: bigR1Commitment,
	}, nil
}

// Round2 executes the secondary cosigner's second round.
func (sc *SecondaryCosigner[P, B, S]) Round2(r1out *Round1OutputP2P[P, B, S]) (r2out *Round2OutputP2P[P, B, S], err error) {
	// Validation
	if sc.round != 2 {
		return nil, ErrRound.WithMessage("Running round %d but secondary cosigner expected round %d", 2, sc.round)
	}
	if err := r1out.Validate(&sc.Cosigner, sc.primarySharingID); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sc.primarySharingID).WithMessage("invalid round 1 output")
	}

	sc.state.bigR1Commitment = r1out.BigR1Commitment
	// step 2.1: k2 <-$ Zq     &    R2 <- k2 * G
	sc.state.k2, err = sc.suite.Curve().ScalarField().Random(sc.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate k2")
	}
	sc.state.bigR2 = sc.suite.Curve().ScalarBaseMul(sc.state.k2)
	// step 2.2: π <- NIPoK.Prove(k2)
	bigR2Proof, err := dlogProve(&sc.Cosigner, sc.state.k2, sc.state.bigR2, sc.primarySharingID)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not prove dlog")
	}

	sc.round += 2
	// step 2.3: Send(R2, π) -> P_1
	return &Round2OutputP2P[P, B, S]{
		BigR2:      sc.state.bigR2,
		BigR2Proof: bigR2Proof,
	}, nil
}

// Round3 executes the primary cosigner's third round.
func (pc *PrimaryCosigner[P, B, S]) Round3(r2out *Round2OutputP2P[P, B, S]) (r3out *Round3OutputP2P[P, B, S], err error) {
	if pc.round != 3 {
		return nil, ErrRound.WithMessage("Running round %d but primary cosigner expected round %d", 3, pc.round)
	}
	if err := r2out.Validate(&pc.Cosigner, pc.secondarySharingID); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pc.secondarySharingID).WithMessage("invalid round 2 output")
	}

	if err := dlogVerify(&pc.Cosigner, pc.niDlogScheme, pc.secondarySharingID, r2out.BigR2Proof, r2out.BigR2, pc.SharingID()); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pc.secondarySharingID).WithMessage("cannot verify R2 dlog proof")
	}

	pc.state.bigR = r2out.BigR2.ScalarMul(pc.state.k1)
	rx, err := pc.state.bigR.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not get bigR x-coordinate")
	}
	pc.state.r, err = pc.suite.Curve().ScalarField().FromWideBytes(rx.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert bigR x-coordinate to scalar")
	}

	pc.round += 2
	return &Round3OutputP2P[P, B, S]{
		BigR1Opening: pc.state.bigR1Opening,
		BigR1:        pc.state.bigR1,
		BigR1Proof:   pc.state.bigR1Proof,
	}, nil
}

// Round4 executes the secondary cosigner's fourth round.
func (sc *SecondaryCosigner[P, B, S]) Round4(r3out *Round3OutputP2P[P, B, S], message []byte) (round4Output *Round4OutputP2P[P, B, S], err error) {
	// Validation
	if sc.round != 4 {
		return nil, ErrRound.WithMessage("Running round %d but secondary cosigner expected round %d", 4, sc.round)
	}
	if err := r3out.Validate(&sc.Cosigner, sc.primarySharingID); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sc.primarySharingID).WithMessage("invalid round 3 output")
	}

	commitmentMessage := bigR1CommitmentMessage(r3out.BigR1, r3out.BigR1Proof)
	if err := sc.commitmentKey.Open(sc.state.bigR1Commitment, commitmentMessage, r3out.BigR1Opening); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sc.primarySharingID).WithMessage("cannot open R1 commitment")
	}

	if err := dlogVerify(&sc.Cosigner, sc.niDlogScheme, sc.primarySharingID, r3out.BigR1Proof, r3out.BigR1, sc.SharingID()); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sc.primarySharingID).WithMessage("cannot verify R1 dlog proof")
	}

	bigR := r3out.BigR1.ScalarMul(sc.state.k2)
	rx, err := bigR.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not get bigR x-coordinate")
	}
	r, err := sc.suite.Curve().ScalarField().FromWideBytes(rx.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert bigR x-coordinate to scalar")
	}

	k2 := sc.state.k2

	paillierPublicKey, exists := sc.shard.PaillierPublicKeys().Get(sc.primarySharingID)
	if !exists || paillierPublicKey == nil {
		return nil, ErrMissing.WithMessage("couldn't get primary paillier public key")
	}
	encryptedPrimaryShares, exists := sc.shard.EncryptedShares().Get(sc.primarySharingID)
	if !exists || len(encryptedPrimaryShares) == 0 {
		return nil, ErrMissing.WithMessage("couldn't get primary encrypted signing key share")
	}
	primaryReconstructionCoefficients, err := sc.shard.MSP().ReconstructionCoefficients(
		sc.primarySharingID,
		sc.signingQuorum.Shareholders().List()...,
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot derive primary reconstruction coefficients")
	}

	mPrime, err := MessageToScalar(sc.suite, message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get scalar from message")
	}

	// Modulo q, c3 encrypts k2^(-1)(m' + r * (x1 + x2)). The primary
	// contribution is converted component-wise under encryption; the secondary
	// contribution and its complementary primary zero share refresh the two
	// effective additive shares for this signing session.
	c3, err := CalcC3(
		k2,
		mPrime,
		r,
		sc.refreshedAdditiveShare,
		sc.zeroShare.Neg(),
		sc.suite.Curve().Order(),
		paillierPublicKey,
		encryptedPrimaryShares,
		primaryReconstructionCoefficients,
		sc.prng,
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot calculate c3")
	}

	sc.round += 2
	return &Round4OutputP2P[P, B, S]{
		C3: c3,
	}, nil
}

// Round5 executes the primary cosigner's final round.
func (pc *PrimaryCosigner[P, B, S]) Round5(r4out *Round4OutputP2P[P, B, S], message []byte) (*ecdsa.Signature[S], error) {
	// Validation
	if pc.round != 5 {
		return nil, ErrRound.WithMessage("Running round %d but primary cosigner expected round %d", 5, pc.round)
	}
	if err := r4out.Validate(&pc.Cosigner, pc.secondarySharingID); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pc.secondarySharingID).WithMessage("invalid round 4 output")
	}
	sPrimePlaintext, err := pc.shard.PaillierSecretKey().Decrypt(r4out.C3)
	if err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pc.secondarySharingID).WithMessage("cannot decrypt c3")
	}
	sPrime, err := paillierPlaintextToScalar(sPrimePlaintext, pc.suite.Curve().ScalarField())
	if err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pc.secondarySharingID).WithMessage("cannot convert decrypted c3 to scalar")
	}
	k1Inv, err := pc.state.k1.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute k1 inverse")
	}
	sDoublePrime := k1Inv.Mul(sPrime)

	v := new(int)
	*v, err = ecdsa.ComputeRecoveryID(pc.state.bigR)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute recovery id")
	}

	signature, err := ecdsa.NewSignature(pc.state.r, sDoublePrime, v)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create signature")
	}
	signature.Normalise()

	ecdsaScheme, err := ecdsa.NewScheme(pc.suite, pc.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ecdsa scheme")
	}
	verifier, err := ecdsaScheme.Verifier()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ecdsa verifier")
	}
	publicKey, err := ecdsa.NewPublicKey(pc.shard.PublicKeyValue())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ECDSA public key")
	}
	if err := verifier.Verify(signature, publicKey, message); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pc.secondarySharingID).WithMessage("could not verify produced signature")
	}
	pc.round += 2
	return signature, nil
}

func dlogProve[
	P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S],
](c *Cosigner[P, B, S], k S, bigR P, otherSharingID sharing.ID) (compiler.NIZKPoKProof, error) {
	proofCtx := c.ctx.Clone()
	proverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(c.SharingID()))
	receiverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(otherSharingID))
	quorumBytes := slices.Concat(proverIDBytes, receiverIDBytes)
	proofCtx.Transcript().AppendBytes(transcriptDLogSLabel, quorumBytes)
	proofCtx.Transcript().AppendBytes(proverLabel, proverIDBytes)
	prover, err := c.niDlogScheme.NewProver(proofCtx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create dlog prover")
	}
	statement := &schnorrpok.Statement[P, S]{
		X: bigR,
	}
	witness := &schnorrpok.Witness[S]{
		W: k,
	}
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create dlog proof")
	}
	return proof, nil
}

func dlogVerify[
	P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S],
](c *Cosigner[P, B, S], niDlogScheme compiler.NonInteractiveProtocol[*schnorrpok.Statement[P, S], *schnorrpok.Witness[S]], proverID sharing.ID, proof compiler.NIZKPoKProof, theirBigR P, mySharingID sharing.ID) error {
	proofCtx := c.ctx.Clone()
	proverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(proverID))
	receiverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(mySharingID))
	quorumBytes := slices.Concat(proverIDBytes, receiverIDBytes)
	proofCtx.Transcript().AppendBytes(transcriptDLogSLabel, quorumBytes)
	proofCtx.Transcript().AppendBytes(proverLabel, proverIDBytes)
	statement := &schnorrpok.Statement[P, S]{
		X: theirBigR,
	}
	verifier, err := niDlogScheme.NewVerifier(proofCtx)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create dlog verifier")
	}
	if err := verifier.Verify(statement, proof); err != nil {
		return errs.Wrap(err).WithMessage("cannot verify dlog proof for participant %d", proverID)
	}
	return nil
}

func bigR1CommitmentMessage[
	P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S],
](bigR1 P, proof compiler.NIZKPoKProof) []byte {
	bigR1Bytes := bigR1.ToCompressed()
	message := binary.BigEndian.AppendUint64(nil, uint64(len(bigR1Bytes)))
	message = append(message, bigR1Bytes...)
	message = binary.BigEndian.AppendUint64(message, uint64(len(proof)))
	return append(message, proof...)
}
