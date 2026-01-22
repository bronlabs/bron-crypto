package sigma

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// Verifier implements the interactive sigma verifier.
type Verifier[X Statement, W Witness, A Commitment, S State, Z Response] struct {
	participant[X, W, A, S, Z]

	prng io.Reader
}

// NewVerifier constructs a sigma protocol verifier.
func NewVerifier[X Statement, W Witness, A Commitment, S State, Z Response](sessionID network.SID, transcript transcripts.Transcript, sigmaProtocol Protocol[X, W, A, S, Z], statement X, prng io.Reader) (*Verifier[X, W, A, S, Z], error) {
	if sigmaProtocol == nil {
		return nil, ErrInvalidArgument.WithMessage("protocol or is nil")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.StatisticalSecurityBits {
		return nil, ErrInvalidArgument.WithMessage("soundness of the interactive protocol (%d) is too low (below %d)", s, base.StatisticalSecurityBits)
	}

	dst := fmt.Sprintf("%s-%s-%s", hex.EncodeToString(sessionID[:]), transcriptLabel, sigmaProtocol.Name())
	transcript.AppendDomainSeparator(dst)
	transcript.AppendBytes(statementLabel, statement.Bytes())

	return &Verifier[X, W, A, S, Z]{
		//nolint:exhaustruct // initial state
		participant: participant[X, W, A, S, Z]{
			sessionID:     sessionID,
			transcript:    transcript,
			sigmaProtocol: sigmaProtocol,
			statement:     statement,
			round:         2,
		},
		prng: prng,
	}, nil
}

// Round2 runs the verifier's second round and samples a challenge.
func (v *Verifier[X, W, A, S, Z]) Round2(commitment A) ([]byte, error) {
	v.transcript.AppendBytes(commitmentLabel, commitment.Bytes())

	if v.round != 2 {
		return nil, ErrRound.WithMessage("r != 2 (%d)", v.round)
	}

	challengeBytes := make([]byte, v.sigmaProtocol.GetChallengeBytesLength())
	_, err := io.ReadFull(v.prng, challengeBytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot read PRNG")
	}

	v.transcript.AppendBytes(challengeLabel, challengeBytes)

	v.commitment = commitment
	v.challengeBytes = challengeBytes
	v.round += 2
	return challengeBytes, nil
}

// Verify checks the prover's response.
func (v *Verifier[X, W, A, S, Z]) Verify(response Z) error {
	v.transcript.AppendBytes(responseLabel, response.Bytes())

	if v.round != 4 {
		return ErrRound.WithMessage("r != 4 (%d)", v.round)
	}

	err := v.sigmaProtocol.Verify(v.statement, v.commitment, v.challengeBytes, response)
	if err != nil {
		return errs.Wrap(err).WithMessage("verification failed")
	}

	return nil
}
