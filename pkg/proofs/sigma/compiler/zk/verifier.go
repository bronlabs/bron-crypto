package zk

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
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
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}
	if sigmaProtocol == nil {
		return nil, errs.NewArgument("protocol or is nil")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.StatisticalSecurityBits {
		return nil, errs.NewArgument("soundness of the interactive protocol (%d) is too low (below %d)", s, base.StatisticalSecurityBits)
	}
	if sigmaProtocol.GetChallengeBytesLength() > k256Impl.FqBytes {
		return nil, errs.NewFailed("challengeBytes is too long for the compiler")
	}

	if tape == nil {
		return nil, errs.NewIsNil("tape is nil")
	}
	dst := fmt.Sprintf("%s-%s-%x", transcriptLabel, sigmaProtocol.Name(), sessionId)
	tape.AppendDomainSeparator(dst)

	tape.AppendBytes(statementLabel, statement.Bytes())

	ck, err := hash_comm.NewKeyFromCRSBytes(sessionId, dst)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create hash commitment key")
	}

	comm, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create commitment scheme")
	}

	return &Verifier[X, W, A, S, Z]{
		participant: participant[X, W, A, S, Z]{
			sessionId: sessionId,
			tape:      tape,
			protocol:  sigmaProtocol,
			comm:      comm,
			statement: statement,
			round:     1,
		},
		prng: prng,
	}, nil
}

// Round1 generates a random challenge, commits to it, and returns the commitment.
// This is the first round of the 5-round protocol.
func (v *Verifier[X, W, A, S, Z]) Round1() (hash_comm.Commitment, error) {
	if v.round != 1 {
		return *new(hash_comm.Commitment), errs.NewRound("r != 1 (%d)", v.round)
	}

	v.challengeBytes = make([]byte, v.protocol.GetChallengeBytesLength())
	_, err := io.ReadFull(v.prng, v.challengeBytes)
	if err != nil {
		return *new(hash_comm.Commitment), errs.WrapRandomSample(err, "couldn't sample challenge")
	}

	eCommitment, eWitness, err := v.comm.Committer().Commit(v.challengeBytes, v.prng)
	if err != nil {
		return *new(hash_comm.Commitment), errs.WrapHashing(err, "couldn't commit to challenge")
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
		return *new(hash_comm.Message), *new(hash_comm.Witness), errs.NewRound("r != 3 (%d)", v.round)
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
		return errs.NewRound("r != 5 (%d)", v.round)
	}

	transcripts.Append(v.tape, responseLabel, response)

	err := v.protocol.Verify(v.statement, v.commitment, v.challengeBytes, response)
	if err != nil {
		return errs.WrapVerification(err, "verification failed")
	}

	return nil
}
