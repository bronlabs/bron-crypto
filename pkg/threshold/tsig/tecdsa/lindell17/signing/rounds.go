package signing

import (
	"encoding/binary"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptDLogSLabel = "Lindell2017SignDLogS-"
	proverLabel          = "Lindell2017SignProver-"
)

// Round1 executes the primary cosigner's first round.
func (pc *PrimaryCosigner[P, B, S]) Round1() (r1out *Round1OutputP2P, err error) {
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
	// step 1.2: c1 <- Commit(sid || Q || R1)
	committer, err := pc.commitmentScheme.Committer()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create committer")
	}
	bigR1Commitment, bigR1Opening, err := committer.Commit(pc.state.bigR1.ToCompressed(), pc.prng) // sid and Q are part of the commitment key
	if err != nil {
		return nil, ErrFailed.WithMessage("cannot commit to R")
	}

	pc.state.bigR1Opening = bigR1Opening

	pc.round += 2
	// step 1.3: Send(c1) -> P_2
	return &Round1OutputP2P{
		BigR1Commitment: bigR1Commitment,
	}, nil
}

// Round2 executes the secondary cosigner's second round.
func (sc *SecondaryCosigner[P, B, S]) Round2(r1out *Round1OutputP2P) (r2out *Round2OutputP2P[P, B, S], err error) {
	// Validation
	if sc.round != 2 {
		return nil, ErrRound.WithMessage("Running round %d but secondary cosigner expected round %d", 2, sc.round)
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

	if err := dlogVerify(pc.tape, pc.niDlogScheme, pc.secondarySharingID, pc.sid, r2out.BigR2Proof, r2out.BigR2, pc.SharingID()); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pc.secondarySharingID).WithMessage("cannot verify R2 dlog proof")
	}

	bigR1Proof, err := dlogProve(&pc.Cosigner, pc.state.k1, pc.state.bigR1, pc.secondarySharingID)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create R1 dlog proof")
	}

	pc.state.bigR = r2out.BigR2.ScalarMul(pc.state.k1)
	rx, err := pc.state.bigR.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not get bigR x-coordinate")
	}
	pc.state.r, err = pc.suite.Curve().ScalarField().FromBytes(rx.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert bigR x-coordinate to scalar")
	}

	pc.round += 2
	return &Round3OutputP2P[P, B, S]{
		BigR1Opening: pc.state.bigR1Opening,
		BigR1:        pc.state.bigR1,
		BigR1Proof:   bigR1Proof,
	}, nil
}

// Round4 executes the secondary cosigner's fourth round.
func (sc *SecondaryCosigner[P, B, S]) Round4(r3out *Round3OutputP2P[P, B, S], message []byte) (round4Output *lindell17.PartialSignature, err error) {
	// Validation
	if sc.round != 4 {
		return nil, ErrRound.WithMessage("Running round %d but secondary cosigner expected round %d", 4, sc.round)
	}

	verifier, err := sc.commitmentScheme.Verifier()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create verifier")
	}
	if err := verifier.Verify(sc.state.bigR1Commitment, r3out.BigR1.ToCompressed(), r3out.BigR1Opening); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot open R1 commitment")
	}

	if err := dlogVerify(sc.tape, sc.niDlogScheme, sc.primarySharingID, sc.sid, r3out.BigR1Proof, r3out.BigR1, sc.SharingID()); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sc.primarySharingID).WithMessage("cannot verify R1 dlog proof")
	}

	bigR := r3out.BigR1.ScalarMul(sc.state.k2)
	rx, err := bigR.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not get bigR x-coordinate")
	}
	r, err := sc.suite.Curve().ScalarField().FromBytes(rx.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert bigR x-coordinate to scalar")
	}

	k2 := sc.state.k2

	quorum := hashset.NewComparable(sc.SharingID(), sc.primarySharingID)
	ac, err := sharing.NewMinimalQualifiedAccessStructure(quorum.Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create access structure for additive sharing")
	}
	additiveShare, err := sc.shard.Share().ToAdditive(ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert Shamir share to additive share")
	}
	paillierPublicKey, exists := sc.shard.PaillierPublicKeys().Get(sc.primarySharingID)
	if !exists {
		return nil, ErrMissing.WithMessage("couldn't get primary paillier public key")
	}
	cKey, exists := sc.shard.EncryptedShares().Get(sc.primarySharingID)
	if !exists {
		return nil, ErrMissing.WithMessage("couldn't get primary encrypted signing key share")
	}

	coefficients, err := shamir.LagrangeCoefficients(sc.suite.Curve().ScalarField(), ac.Shareholders().List()...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get Lagrange coefficients")
	}
	primaryLagrangeCoefficient, exists := coefficients.Get(sc.primarySharingID)
	if !exists {
		return nil, ErrMissing.WithMessage("could not get primary Lagrange coefficient")
	}

	mPrime, err := MessageToScalar(sc.suite, message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get scalar from message")
	}

	// c3 = Enc(ρq + k2^(-1)(m' + r * (y1 * λ1 + y2 * λ2)))
	c3, err := CalcC3(primaryLagrangeCoefficient, k2, mPrime, r, additiveShare.Value(), sc.suite.Curve().Order(), paillierPublicKey, cKey, sc.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot calculate c3")
	}

	sc.round += 2
	return &lindell17.PartialSignature{
		C3: c3,
	}, nil
}

// Round5 executes the primary cosigner's final round.
func (pc *PrimaryCosigner[P, B, S]) Round5(r4out *lindell17.PartialSignature, message []byte) (*ecdsa.Signature[S], error) {
	// Validation
	if pc.round != 5 {
		return nil, ErrRound.WithMessage("Running round %d but primary cosigner expected round %d", 5, pc.round)
	}
	decrypter, err := paillier.NewScheme().Decrypter(pc.shard.PaillierPrivateKey())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create paillier decrypter")
	}
	sPrimeInt, err := decrypter.Decrypt(r4out.C3)
	if err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pc.secondarySharingID).WithMessage("cannot decrypt c3")
	}
	sPrime, err := pc.suite.Curve().ScalarField().FromBytesBEReduce(sPrimeInt.Normalise().BytesBE())
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
	if err := verifier.Verify(signature, pc.shard.PublicKey(), message); err != nil {
		return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pc.secondarySharingID).WithMessage("could not verify produced signature")
	}
	pc.round += 2
	return signature, nil
}

func dlogProve[
	P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S],
](c *Cosigner[P, B, S], k S, bigR P, otherSharingID sharing.ID) (compiler.NIZKPoKProof, error) {
	proverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(c.SharingID()))
	receiverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(otherSharingID))
	quorumBytes := slices.Concat(proverIDBytes, receiverIDBytes)
	c.tape.AppendBytes(transcriptDLogSLabel, quorumBytes)
	c.tape.AppendBytes(proverLabel, proverIDBytes)
	prover, err := c.niDlogScheme.NewProver(c.sid, c.tape)
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
](tape transcripts.Transcript, niDlogScheme compiler.NonInteractiveProtocol[*schnorrpok.Statement[P, S], *schnorrpok.Witness[S]], proverID sharing.ID, sid network.SID, proof compiler.NIZKPoKProof, theirBigR P, mySharingID sharing.ID) error {
	proverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(proverID))
	receiverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(mySharingID))
	quorumBytes := slices.Concat(proverIDBytes, receiverIDBytes)
	tape.AppendBytes(transcriptDLogSLabel, quorumBytes)
	tape.AppendBytes(proverLabel, proverIDBytes)
	statement := &schnorrpok.Statement[P, S]{
		X: theirBigR,
	}
	verifier, err := niDlogScheme.NewVerifier(sid, tape)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create dlog verifier")
	}
	if err := verifier.Verify(statement, proof); err != nil {
		return errs.Wrap(err).WithMessage("cannot verify dlog proof for participant %d", proverID)
	}
	return nil
}
