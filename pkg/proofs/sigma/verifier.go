package sigma

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Verifier[X Statement, W Witness, A Commitment, S State, Z Response] struct {
	participant[X, W, A, S, Z]
}

func NewVerifier[X Statement, W Witness, A Commitment, S State, Z Response](baseParticipant types.Participant[Protocol[X, W, A, S, Z]], statement X) (*Verifier[X, W, A, S, Z], error) {
	verifier := &Verifier[X, W, A, S, Z]{
		participant: participant[X, W, A, S, Z]{
			Participant: baseParticipant,
			statement:   statement,
		},
	}
	if err := verifier.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "couldn't validate %s verifier", verifier.Protocol().Name())
	}
	dst := fmt.Sprintf("%s-%s", transcriptLabel, verifier.Protocol().Name())
	if err := verifier.Initialise(2, dst); err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise verifier")
	}
	verifier.Transcript().AppendMessages(statementLabel, verifier.Protocol().SerializeStatement(statement))

	return verifier, nil
}

func (v *Verifier[X, W, A, S, Z]) Round2(commitment A) ([]byte, error) {
	v.Transcript().AppendMessages(commitmentLabel, v.Protocol().SerializeCommitment(commitment))

	if v.Round() != 2 {
		return nil, errs.NewRound("r != 2 (%d)", v.Round())
	}

	challengeBytes := make([]byte, v.Protocol().GetChallengeBytesLength())
	_, err := io.ReadFull(v.Prng(), challengeBytes)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot read PRNG")
	}

	v.Transcript().AppendMessages(challengeLabel, challengeBytes)

	v.commitment = commitment
	v.challengeBytes = challengeBytes
	v.NextRound(4)
	return challengeBytes, nil
}

func (v *Verifier[X, W, A, S, Z]) Verify(response Z) error {
	v.Transcript().AppendMessages(responseLabel, v.Protocol().SerializeResponse(response))

	if v.Round() != 4 {
		return errs.NewRound("r != 4 (%d)", v.Round())
	}

	err := v.Protocol().Verify(v.statement, v.commitment, v.challengeBytes, response)
	if err != nil {
		return errs.WrapVerification(err, "verification failed")
	}
	v.response = response
	return nil
}
