package sigma

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Verifier[X Statement, W Witness, A Commitment, S CommitmentState, E Challenge, Z Response] struct {
	participant[X, W, A, S, E, Z]

	prng io.Reader
}

func NewVerifier[X Statement, W Witness, A Commitment, S CommitmentState, E Challenge, Z Response](sessionId []byte, transcript transcripts.Transcript, sigmaProtocol Protocol[X, W, A, S, E, Z], statement X, prng io.Reader) (*Verifier[X, W, A, S, E, Z], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("sessionId is empty")
	}
	if sigmaProtocol == nil {
		return nil, errs.NewInvalidArgument("protocol or is nil")
	}

	if transcript == nil {
		dst := fmt.Sprintf("%s-%s", domainSeparationTag, sigmaProtocol.DomainSeparationLabel())
		transcript = hagrid.NewTranscript(dst, nil)
	}
	transcript.AppendMessages(sessionIdLabel, sessionId)
	transcript.AppendMessages(statementLabel, sigmaProtocol.SerializeStatement(statement))

	return &Verifier[X, W, A, S, E, Z]{
		participant: participant[X, W, A, S, E, Z]{
			sessionId:     sessionId,
			transcript:    transcript,
			sigmaProtocol: sigmaProtocol,
			statement:     statement,
			round:         2,
		},
		prng: prng,
	}, nil
}

func (v *Verifier[X, W, A, S, E, Z]) Round2(commitment A) (E, error) {
	var zero E
	v.transcript.AppendMessages(commitmentLabel, v.sigmaProtocol.SerializeCommitment(commitment))

	if v.round != 2 {
		return zero, errs.NewInvalidRound("r != 2 (%d)", v.round)
	}

	entropy := make([]byte, 32)
	_, err := io.ReadFull(v.prng, entropy)
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot read PRNG")
	}

	challenge, err := v.sigmaProtocol.GenerateChallenge(entropy)
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot generate challenge")
	}
	v.transcript.AppendMessages(challengeLabel, v.sigmaProtocol.SerializeChallenge(challenge))

	v.commitment = commitment
	v.challenge = challenge
	v.round += 2
	return challenge, nil
}

func (v *Verifier[X, W, A, S, E, Z]) Verify(response Z) error {
	v.transcript.AppendMessages(responseLabel, v.sigmaProtocol.SerializeResponse(response))

	if v.round != 4 {
		return errs.NewInvalidRound("r != 4 (%d)", v.round)
	}

	err := v.sigmaProtocol.Verify(v.statement, v.commitment, v.challenge, response)
	if err != nil {
		return errs.WrapVerificationFailed(err, "verification failed")
	}

	return nil
}
