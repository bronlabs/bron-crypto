package zkcompiler

import (
	"fmt"
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
)

type Verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	participant[X, W, A, S, Z]

	eWitness hashcommitments.Witness
	prng     io.Reader
}

func NewVerifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](sessionId []byte, tape transcripts.Transcript, sigmaProtocol sigma.Protocol[X, W, A, S, Z], statement X, prng io.Reader) (*Verifier[X, W, A, S, Z], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}
	if sigmaProtocol == nil {
		return nil, errs.NewArgument("protocol or is nil")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.StatisticalSecurity {
		return nil, errs.NewArgument("soundness of the interactive protocol (%d) is too low (below %d)", s, base.StatisticalSecurity)
	}

	crs, err := tape.Bind(sessionId, fmt.Sprintf("%s-%s", sigmaProtocol.Name(), transcriptLabel))
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}
	tape.AppendMessages(statementLabel, sigmaProtocol.SerializeStatement(statement))

	ck, err := hashcommitments.NewCommittingKeyFromCrsBytes(sessionId, crs)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create committingKey")
	}

	return &Verifier[X, W, A, S, Z]{
		participant: participant[X, W, A, S, Z]{
			sessionId: sessionId,
			tape:      tape,
			protocol:  sigmaProtocol,
			ck:        ck,
			statement: statement,
			round:     1,
		},
		prng: prng,
	}, nil
}

func (v *Verifier[X, W, A, S, Z]) Round1() (hashcommitments.Commitment, error) {
	if v.round != 1 {
		return hashcommitments.Commitment{}, errs.NewRound("r != 1 (%d)", v.round)
	}

	v.challengeBytes = make([]byte, v.protocol.GetChallengeBytesLength())
	_, err := io.ReadFull(v.prng, v.challengeBytes)
	if err != nil {
		return hashcommitments.Commitment{}, errs.WrapRandomSample(err, "couldn't sample challenge")
	}

	eCommitment, eWitness, err := v.ck.Commit(hashcommitments.Message(v.challengeBytes), v.prng)
	if err != nil {
		return hashcommitments.Commitment{}, errs.WrapHashing(err, "couldn't commit to challenge")
	}
	v.eWitness = eWitness

	v.tape.AppendMessages(challengeCommitmentLabel, eCommitment[:])
	v.round += 2
	return eCommitment, nil
}

func (v *Verifier[X, W, A, S, Z]) Round3(commitment A) (*commitments.Opening[hashcommitments.Message, hashcommitments.Witness], error) {
	v.tape.AppendMessages(commitmentLabel, v.protocol.SerializeCommitment(commitment))

	if v.round != 3 {
		return nil, errs.NewRound("r != 3 (%d)", v.round)
	}

	v.tape.AppendMessages(challengeLabel, v.challengeBytes)

	v.commitment = commitment
	v.round += 2
	return commitments.NewOpening(hashcommitments.Message(v.challengeBytes), v.eWitness), nil
}

func (v *Verifier[X, W, A, S, Z]) Verify(response Z) error {
	v.tape.AppendMessages(responseLabel, v.protocol.SerializeResponse(response))

	if v.round != 5 {
		return errs.NewRound("r != 5 (%d)", v.round)
	}

	err := v.protocol.Verify(v.statement, v.commitment, v.challengeBytes, response)
	if err != nil {
		return errs.WrapVerification(err, "verification failed")
	}

	return nil
}
