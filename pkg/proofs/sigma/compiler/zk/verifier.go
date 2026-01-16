package zk

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// Verifier is the verifier in the zero-knowledge compiled protocol.
// It participates in rounds 1, 3, and 5 (verification) of the 5-round protocol.
type Verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	participant[X, W, A, S, Z]

	challengeBytes []byte
	eWitness       hash_comm.Witness
	prng           io.Reader
}

// NewVerifier creates a new verifier for the zero-knowledge compiled protocol.
// The sigma protocol must have soundness error at least 2^(-80) (statistical security).
// The prng is used to sample the random challenge. The verifier will execute
// rounds 1, 3, and 5 of the protocol.
func NewVerifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](sessionId network.SID, tape transcripts.Transcript, sigmaProtocol sigma.Protocol[X, W, A, S, Z], statement X, prng io.Reader) (*Verifier[X, W, A, S, Z], error) {
	if prng == nil {
		return nil, ErrNil.WithMessage("prng")
	}
	p, err := newParticipant(sessionId, tape, sigmaProtocol, statement)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create participant")
	}
	return &Verifier[X, W, A, S, Z]{
		participant: *p,
		prng:        prng,
	}, nil
}

// Round1 generates a random challenge, commits to it, and returns the commitment.
// This is the first round of the 5-round protocol.
func (v *Verifier[X, W, A, S, Z]) Round1() (hash_comm.Commitment, error) {
	if v.round != 1 {
		return *new(hash_comm.Commitment), ErrRound.WithMessage("r != 1 (%d)", v.round)
	}

	v.challengeBytes = make([]byte, v.protocol.GetChallengeBytesLength())
	_, err := io.ReadFull(v.prng, v.challengeBytes)
	if err != nil {
		return *new(hash_comm.Commitment), errs2.Wrap(err).WithMessage("couldn't sample challenge")
	}

	eCommitment, eWitness, err := v.comm.Committer().Commit(v.challengeBytes, v.prng)
	if err != nil {
		return *new(hash_comm.Commitment), errs2.Wrap(err).WithMessage("couldn't commit to challenge")
	}
	v.eWitness = eWitness

	transcripts.Append(v.tape, challengeCommitmentLabel, eCommitment)
	v.round += 2
	return eCommitment, nil
}

// Round3 receives the prover's commitment and opens the challenge commitment.
// Returns the challenge message and witness for the prover to verify.
func (v *Verifier[X, W, A, S, Z]) Round3(commitment A) (hash_comm.Message, hash_comm.Witness, error) {
	if v.round != 3 {
		return *new(hash_comm.Message), *new(hash_comm.Witness), ErrRound.WithMessage("r != 3 (%d)", v.round)
	}
	transcripts.Append(v.tape, commitmentLabel, commitment)
	v.tape.AppendBytes(challengeLabel, v.challengeBytes)

	v.commitment = commitment
	v.round += 2

	return v.challengeBytes, v.eWitness, nil
}

// Verify checks the prover's response against the sigma protocol.
// Returns nil if verification succeeds, or an error if it fails.
func (v *Verifier[X, W, A, S, Z]) Verify(response Z) error {
	if v.round != 5 {
		return ErrRound.WithMessage("r != 5 (%d)", v.round)
	}

	transcripts.Append(v.tape, responseLabel, response)

	err := v.protocol.Verify(v.statement, v.commitment, v.challengeBytes, response)
	if err != nil {
		return errs2.Wrap(err).WithMessage("verification failed")
	}

	return nil
}
