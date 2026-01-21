package signing

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const transcriptDLogSLabel = "Lindell2022SignDLogS-"

// Round1 samples a random nonce, commits to it, and broadcasts the commitment.
func (c *Cosigner[E, S, M]) Round1() (*Round1Broadcast, error) {
	if c.round != 1 {
		return nil, ErrInvalidRound.WithMessage("Running round %d but participant expected round %d", 1, c.round)
	}

	// step 1.1: Sample k_i <-$- ℤ_q  &  compute R_i = k_i * G
	// We won't use ComputeNonceCommitment of single party schnorr due to requiring message independence.
	// Any usable single party schnorr variant will have extra methods to allows us to correct parity and alike later.
	k, err := algebrautils.RandomNonIdentity(c.sf, c.prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create randomised nonce commitment")
	}
	bigR := c.group.ScalarBaseOp(k)

	// step 1.2: Run c_i <= commit(sid || R_i || i || S)
	commitment, opening, err := commitBigR(c, bigR)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot commit to R")
	}

	// step 1.4: Broadcast(c_i)
	broadcast := &Round1Broadcast{
		BigRCommitment: commitment,
	}

	c.state.k = k
	c.state.bigR = bigR
	c.state.opening = opening
	c.round++

	return broadcast, nil
}

// Round2 receives commitments from other parties and broadcasts the nonce with a discrete log proof.
func (c *Cosigner[E, S, M]) Round2(inb network.RoundMessages[*Round1Broadcast]) (*Round2Broadcast[E, S], error) {
	if c.round != 2 {
		return nil, ErrInvalidRound.WithMessage("Running round %d but participant expected round %d", 2, c.round)
	}
	for pid := range c.quorum.Iter() {
		if c.SharingID() == pid {
			continue // skip self
		}
		received, _ := inb.Get(pid)
		c.state.theirBigRCommitments[pid] = received.BigRCommitment
	}
	// step 2.1: π^dl_i <- NIPoKDL.Prove(k_i, R_i, sessionID, S, nic)
	c.state.tapeFrozenBeforeDlogProof = c.tape.Clone()
	bigRProof, statement, err := dlogProve(c, c.state.k, c.state.bigR, c.state.quorumBytes)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot prove dlog")
	}

	// step 2.3: Broadcast(π^dl_i, R_i, c_i)
	broadcast := &Round2Broadcast[E, S]{
		BigR:        statement,
		BigROpening: c.state.opening,
		BigRProof:   bigRProof,
	}

	c.round++
	return broadcast, nil
}

// Round3 verifies other parties' commitments and proofs, then computes the partial signature.
func (c *Cosigner[E, S, M]) Round3(inb network.RoundMessages[*Round2Broadcast[E, S]], message M) (*tschnorr.PartialSignature[E, S], error) {
	if c.round != 3 {
		return nil, ErrInvalidRound.WithMessage("Running round %d but participant expected round %d", 3, c.round)
	}
	summedR := c.state.bigR
	for pid := range c.quorum.Iter() {
		if c.SharingID() == pid {
			continue // skip self
		}
		received, _ := inb.Get(pid)
		theirBigR := received.BigR
		theirOpening := received.BigROpening
		theirCommitment := c.state.theirBigRCommitments[pid]
		// step 3.2: Open(sid || R_j || j || S)
		if err := verifyBigRCommitment(c, pid, theirBigR.X, theirOpening, theirCommitment); err != nil {
			return nil, errs2.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("cannot verify commitment for participant")
		}
		// step 3.3: Run NIPoKDL.Verify(R_j, π^dl_j)
		if err := dlogVerify(
			c.state.tapeFrozenBeforeDlogProof.Clone(), c.niDlogScheme, pid, c.sid, received.BigRProof, theirBigR, c.state.quorumBytes,
		); err != nil {
			return nil, errs2.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("cannot verify dlog proof for participant")
		}
		// step 3.4: R <- Σ R_j
		summedR = summedR.Op(theirBigR.X)
	}
	// step 3.7.2: compute e
	e, err := c.variant.ComputeChallenge(summedR, c.shard.PublicKey().Value(), message)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create digest scalar")
	}

	psig, err := c.ComputePartialSignature(summedR, e)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot compute partial signature")
	}
	c.round++
	return psig, nil
}

func commitBigR[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
](c *Cosigner[E, S, M], bigR E) (commitment lindell22.Commitment, opening lindell22.Opening, err error) {
	key, err := lindell22.NewCommitmentKey(c.sid, c.SharingID(), c.state.quorumBytes)
	if err != nil {
		return lindell22.Commitment{}, lindell22.Opening{}, errs2.Wrap(err).WithMessage("cannot create commitment key")
	}
	// step 1.2: Run c_i <= commit(sid || R_i || i || S)
	commitmentScheme, err := lindell22.NewCommitmentScheme(key)
	if err != nil {
		return lindell22.Commitment{}, lindell22.Opening{}, errs2.Wrap(err).WithMessage("cannot create commitment scheme")
	}
	committer, err := commitmentScheme.Committer()
	if err != nil {
		return lindell22.Commitment{}, lindell22.Opening{}, errs2.Wrap(err).WithMessage("cannot create commitment committer")
	}
	commitment, opening, err = committer.Commit(bigR.Bytes(), c.prng)
	if err != nil {
		return lindell22.Commitment{}, lindell22.Opening{}, errs2.Wrap(err).WithMessage("cannot commit to R")
	}
	return commitment, opening, nil
}

func verifyBigRCommitment[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
](c *Cosigner[E, S, M], theirID sharing.ID, theirBigR E, theirOpening lindell22.Opening, theirCommitment lindell22.Commitment) error {
	key, err := lindell22.NewCommitmentKey(c.sid, theirID, c.state.quorumBytes)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot create commitment key for participant %d", theirID)
	}
	commitmentScheme, err := lindell22.NewCommitmentScheme(key)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot create commitment scheme for participant %d", theirID)
	}
	verifier, err := commitmentScheme.Verifier()
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot create commitment verifier for participant %d", theirID)
	}
	if err := verifier.Verify(theirCommitment, theirBigR.Bytes(), theirOpening); err != nil {
		return errs2.Wrap(err).WithMessage("cannot verify commitment for participant %d", theirID)
	}
	return nil
}

func dlogProve[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
](c *Cosigner[E, S, M], k S, bigR E, quorumBytes [][]byte) (proof compiler.NIZKPoKProof, statement *schnorrpok.Statement[E, S], err error) {
	proverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(c.SharingID()))
	c.tape.AppendBytes(transcriptDLogSLabel, quorumBytes...)
	c.tape.AppendBytes("prover", proverIDBytes)
	prover, err := c.niDlogScheme.NewProver(c.sid, c.tape)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot create dlog prover")
	}
	statement = &schnorrpok.Statement[E, S]{
		X: bigR,
	}
	witness := &schnorrpok.Witness[S]{
		W: k,
	}
	proof, err = prover.Prove(statement, witness)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot create dlog proof")
	}
	return proof, statement, nil
}

func dlogVerify[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
](tape ts.Transcript, niDlogScheme compiler.NonInteractiveProtocol[*schnorrpok.Statement[E, S], *schnorrpok.Witness[S]], proverID sharing.ID, sid network.SID, proof compiler.NIZKPoKProof, theirBigR *schnorrpok.Statement[E, S], quorumBytes [][]byte) error {
	proverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(proverID))
	tape.AppendBytes(transcriptDLogSLabel, quorumBytes...)
	tape.AppendBytes("prover", proverIDBytes)
	verifier, err := niDlogScheme.NewVerifier(sid, tape)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot create dlog verifier")
	}
	if err := verifier.Verify(theirBigR, proof); err != nil {
		return errs2.Wrap(err).WithMessage("cannot verify dlog proof for participant %d", proverID)
	}
	return nil
}
