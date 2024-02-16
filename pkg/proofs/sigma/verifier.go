package sigma

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Verifier[X Statement, W Witness, A Commitment, S State, Z Response] struct {
	participant[X, W, A, S, Z]

	prng io.Reader
}

func NewVerifier[X Statement, W Witness, A Commitment, S State, Z Response](sessionId []byte, transcript transcripts.Transcript, sigmaProtocol Protocol[X, W, A, S, Z], statement X, prng io.Reader) (*Verifier[X, W, A, S, Z], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}
	if sigmaProtocol == nil {
		return nil, errs.NewArgument("protocol or is nil")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, sigmaProtocol.Name())
	transcript, sessionId, err := hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}
	transcript.AppendMessages(statementLabel, sigmaProtocol.SerializeStatement(statement))

	return &Verifier[X, W, A, S, Z]{
		participant: participant[X, W, A, S, Z]{
			sessionId:     sessionId,
			transcript:    transcript,
			sigmaProtocol: sigmaProtocol,
			statement:     statement,
			round:         2,
		},
		prng: prng,
	}, nil
}

func (v *Verifier[X, W, A, S, Z]) Round2(commitment A) ([]byte, error) {
	v.transcript.AppendMessages(commitmentLabel, v.sigmaProtocol.SerializeCommitment(commitment))

	if v.round != 2 {
		return nil, errs.NewRound("r != 2 (%d)", v.round)
	}

	challengeBytes := make([]byte, v.sigmaProtocol.GetChallengeBytesLength())
	_, err := io.ReadFull(v.prng, challengeBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot read PRNG")
	}

	v.transcript.AppendMessages(challengeLabel, challengeBytes)

	v.commitment = commitment
	v.challengeBytes = challengeBytes
	v.round += 2
	return challengeBytes, nil
}

func (v *Verifier[X, W, A, S, Z]) Verify(response Z) error {
	v.transcript.AppendMessages(responseLabel, v.sigmaProtocol.SerializeResponse(response))

	if v.round != 4 {
		return errs.NewRound("r != 4 (%d)", v.round)
	}

	err := v.sigmaProtocol.Verify(v.statement, v.commitment, v.challengeBytes, response)
	if err != nil {
		return errs.WrapVerification(err, "verification failed")
	}

	return nil
}
