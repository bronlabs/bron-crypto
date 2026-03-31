package signing

import (
	"encoding/binary"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

const transcriptDLogSLabel = "Lindell2022SignDLogS-"

// Round1 samples a random nonce, commits to it, and broadcasts the commitment.
func (c *Cosigner[E, S, M]) Round1() (*Round1Broadcast[E, S, M], error) {
	if c.round != 1 {
		return nil, ErrInvalidRound.WithMessage("Running round %d but participant expected round %d", 1, c.round)
	}

	// step 1.1: Sample k_i <-$- ℤ_q  &  compute R_i = k_i * G
	// We won't use ComputeNonceCommitment of single party schnorr due to requiring message independence.
	// Any usable single party schnorr variant will have extra methods to allows us to correct parity and alike later.
	k, err := algebrautils.RandomNonIdentity(c.sf, c.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create randomised nonce commitment")
	}
	bigR := c.group.ScalarBaseOp(k)

	// step 1.2: Run c_i <= commit(sid || R_i || i || S)
	commitment, opening, err := commitBigR(c, bigR)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot commit to R")
	}

	// step 1.4: Broadcast(c_i)
	broadcast := &Round1Broadcast[E, S, M]{
		BigRCommitment: commitment,
	}

	c.state.k = k
	c.state.bigR = bigR
	c.state.opening = opening

	c.round++
	return broadcast, nil
}

// Round2 receives commitments from other parties and broadcasts the nonce with a discrete log proof.
func (c *Cosigner[E, S, M]) Round2(inb network.RoundMessages[*Round1Broadcast[E, S, M], *Cosigner[E, S, M]]) (*Round2Broadcast[E, S, M], error) {
	if c.round != 2 {
		return nil, ErrInvalidRound.WithMessage("Running round %d but participant expected round %d", 2, c.round)
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), inb); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid input")
	}

	for pid := range c.ctx.OtherPartiesOrdered() {
		received, _ := inb.Get(pid)
		c.state.theirBigRCommitments[pid] = received.BigRCommitment
	}
	// step 2.1: π^dl_i <- NIPoKDL.Prove(k_i, R_i, sessionID, S, nic)
	c.state.ctxFrozenBeforeDlogProof = c.ctx.Clone()
	bigRProof, statement, err := dlogProve(c, c.state.k, c.state.bigR, c.state.quorumBytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot prove dlog")
	}

	// step 2.3: Broadcast(π^dl_i, R_i, c_i)
	broadcast := &Round2Broadcast[E, S, M]{
		BigR:        statement,
		BigROpening: c.state.opening,
		BigRProof:   bigRProof,
	}

	c.round++
	return broadcast, nil
}

// Round3 verifies other parties' commitments and proofs, then computes the partial signature.
func (c *Cosigner[E, S, M]) Round3(inb network.RoundMessages[*Round2Broadcast[E, S, M], *Cosigner[E, S, M]], message M) (*lindell22.PartialSignature[E, S], error) {
	if c.round != 3 {
		return nil, ErrInvalidRound.WithMessage("Running round %d but participant expected round %d", 3, c.round)
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), inb); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid input")
	}

	for pid := range c.ctx.OtherPartiesOrdered() {
		received, _ := inb.Get(pid)
		theirBigR := received.BigR
		theirOpening := received.BigROpening
		theirCommitment := c.state.theirBigRCommitments[pid]
		// step 3.2: Open(sid || R_j || j || S)
		if err := verifyBigRCommitment(c, pid, theirBigR.X, theirOpening, theirCommitment); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("cannot verify commitment for participant")
		}
		// step 3.3: Run NIPoKDL.Verify(R_j, π^dl_j)
		if err := dlogVerify(
			c.state.ctxFrozenBeforeDlogProof.Clone(), c.niDlogScheme, pid, received.BigRProof, theirBigR, c.state.quorumBytes,
		); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("cannot verify dlog proof for participant")
		}
		// step 3.4: R <- Σ R_j
		c.state.bigR = c.state.bigR.Op(theirBigR.X)
	}
	// step 3.7.2: compute e
	e, err := c.variant.ComputeChallenge(c.state.bigR, c.shard.PublicKey().Value(), message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create digest scalar")
	}

	psig, err := c.ComputePartialSignature(c.state.bigR, e)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute partial signature")
	}

	// For identifiable abort, we need to keep track of Ri for all parties, even though we won't be using them if the protocol doesn't abort. So we save the corrected bigR for each party in the state.
	for pid := range c.ctx.OtherPartiesOrdered() {
		received, _ := inb.Get(pid)
		theirBigR := received.BigR
		c.state.correctedBigRs[pid], err = c.variant.CorrectPartialNonceCommitmentParity(c.state.bigR, theirBigR.X)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("cannot correct partial nonce commitment parity for participant")
		}
	}
	c.state.correctedBigRs[c.ctx.HolderID()] = psig.Sig.R

	c.round++
	return psig, nil
}

// ComputePartialSignature computes this party's contribution to the aggregate signature.
func (c *Cosigner[GE, S, M]) ComputePartialSignature(aggregatedNonceCommitment GE, challenge S) (*lindell22.PartialSignature[GE, S], error) {
	if c == nil {
		return nil, ErrNilArgument.WithMessage("cosigner cannot be nil")
	}
	if c.round != 3 {
		return nil, ErrInvalidRound.WithMessage("cosigner %d cannot compute partial signature in round %d, expected round 3", c.ctx.HolderID(), c.round)
	}

	quorum, err := unanimity.NewUnanimityAccessStructure(c.Quorum())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create minimal qualified access structure for quorum %v", c.Quorum())
	}
	zero, err := przs.SampleZeroShare(c.ctx, c.sf)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample zero share")
	}
	ashare, err := c.lsss.ConvertShareToAdditive(c.shard.Share(), quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert share %d to additive share", c.shard.Share().ID())
	}
	ashare = ashare.Add(zero)
	shift := c.group.ScalarBaseOp(zero.Value())

	myAdditiveShare, err := c.variant.CorrectAdditiveSecretShareParity(c.shard.PublicKey(), ashare)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot correct share %d parity", c.shard.Share().ID())
	}
	correctedR, correctedK, err := c.variant.CorrectPartialNonceParity(aggregatedNonceCommitment, c.state.k)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot correct nonce parity")
	}
	s, err := c.variant.ComputeResponse(myAdditiveShare.Value(), correctedK, challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute response")
	}
	return &lindell22.PartialSignature[GE, S]{
		Sig: schnorrlike.Signature[GE, S]{
			E: challenge,
			R: correctedR,
			S: s,
		},
		ZeroPublicKeyShift: shift,
	}, nil
}

func commitBigR[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
](c *Cosigner[E, S, M], bigR E) (commitment lindell22.Commitment, opening lindell22.Opening, err error) {
	key, err := lindell22.NewCommitmentKey(c.ctx.SessionID(), c.SharingID(), c.state.quorumBytes)
	if err != nil {
		return lindell22.Commitment{}, lindell22.Opening{}, errs.Wrap(err).WithMessage("cannot create commitment key")
	}
	// step 1.2: Run c_i <= commit(sid || R_i || i || S)
	commitmentScheme, err := lindell22.NewCommitmentScheme(key)
	if err != nil {
		return lindell22.Commitment{}, lindell22.Opening{}, errs.Wrap(err).WithMessage("cannot create commitment scheme")
	}
	committer, err := commitmentScheme.Committer()
	if err != nil {
		return lindell22.Commitment{}, lindell22.Opening{}, errs.Wrap(err).WithMessage("cannot create commitment committer")
	}
	commitment, opening, err = committer.Commit(bigR.Bytes(), c.prng)
	if err != nil {
		return lindell22.Commitment{}, lindell22.Opening{}, errs.Wrap(err).WithMessage("cannot commit to R")
	}
	return commitment, opening, nil
}

func verifyBigRCommitment[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
](c *Cosigner[E, S, M], theirID sharing.ID, theirBigR E, theirOpening lindell22.Opening, theirCommitment lindell22.Commitment) error {
	key, err := lindell22.NewCommitmentKey(c.ctx.SessionID(), theirID, c.state.quorumBytes)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create commitment key for participant %d", theirID)
	}
	commitmentScheme, err := lindell22.NewCommitmentScheme(key)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create commitment scheme for participant %d", theirID)
	}
	verifier, err := commitmentScheme.Verifier()
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create commitment verifier for participant %d", theirID)
	}
	if err := verifier.Verify(theirCommitment, theirBigR.Bytes(), theirOpening); err != nil {
		return errs.Wrap(err).WithMessage("cannot verify commitment for participant %d", theirID)
	}
	return nil
}

func dlogProve[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
](c *Cosigner[E, S, M], k S, bigR E, quorumBytes [][]byte) (proof compiler.NIZKPoKProof, statement *schnorrpok.Statement[E, S], err error) {
	proverCtx := c.ctx.Clone()
	proverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(c.SharingID()))
	proverCtx.Transcript().AppendBytes(transcriptDLogSLabel, quorumBytes...)
	proverCtx.Transcript().AppendBytes("prover", proverIDBytes)
	prover, err := c.niDlogScheme.NewProver(proverCtx)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create dlog prover")
	}
	statement = &schnorrpok.Statement[E, S]{
		X: bigR,
	}
	witness := &schnorrpok.Witness[S]{
		W: k,
	}
	proof, err = prover.Prove(statement, witness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create dlog proof")
	}
	return proof, statement, nil
}

func dlogVerify[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
](proverCtx *session.Context, niDlogScheme compiler.NonInteractiveProtocol[*schnorrpok.Statement[E, S], *schnorrpok.Witness[S]], proverID sharing.ID, proof compiler.NIZKPoKProof, theirBigR *schnorrpok.Statement[E, S], quorumBytes [][]byte) error {
	proverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(proverID))
	proverCtx.Transcript().AppendBytes(transcriptDLogSLabel, quorumBytes...)
	proverCtx.Transcript().AppendBytes("prover", proverIDBytes)
	verifier, err := niDlogScheme.NewVerifier(proverCtx)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create dlog verifier")
	}
	if err := verifier.Verify(theirBigR, proof); err != nil {
		return errs.Wrap(err).WithMessage("cannot verify dlog proof for participant %d", proverID)
	}
	return nil
}
