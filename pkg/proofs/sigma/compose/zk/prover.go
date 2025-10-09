package zkcompiler

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	pedersen_comm "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

type Prover[X sigma.Statement, XV pedersen_comm.GroupElement[XV, WV], W sigma.Witness, WV pedersen_comm.Scalar[WV], A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	participant[X, XV, W, WV, A, S, Z]

	challengeCommitment *pedersen_comm.Commitment[XV, WV]
	witness             W
	state               S
}

func NewProver[X sigma.Statement, XV pedersen_comm.GroupElement[XV, WV], W sigma.Witness, WV pedersen_comm.Scalar[WV], A sigma.Commitment, S sigma.State, Z sigma.Response](sessionId network.SID, tape transcripts.Transcript, sigmaProtocol sigma.Protocol[X, W, A, S, Z], pedersenGroup pedersen_comm.Group[XV, WV], statement X, witness W) (*Prover[X, XV, W, WV, A, S, Z], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}
	if sigmaProtocol == nil {
		return nil, errs.NewArgument("protocol, statement or witness is nil")
	}
	if pedersenGroup == nil {
		return nil, errs.NewIsNil("pedersenGroup is nil")
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
	dst := fmt.Sprintf("%s-%s-%s-%x", transcriptLabel, sigmaProtocol.Name(), pedersenGroup.Name(), sessionId)
	tape.AppendDomainSeparator(dst)

	hBytes, err := tape.ExtractBytes("H", uint(pedersenGroup.ElementSize()))
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't extract H bytes from the transcript")
	}

	ck, err := pedersen_comm.NewCommitmentKeyFromHBytes(pedersenGroup, hBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create commitment key from H bytes")
	}

	return &Prover[X, XV, W, WV, A, S, Z]{
		participant: participant[X, XV, W, WV, A, S, Z]{
			sessionId:     sessionId,
			tape:          tape,
			ck:            ck,
			protocol:      sigmaProtocol,
			statement:     statement,
			pedersenGroup: pedersenGroup,
			round:         2,
		},
		witness: witness,
	}, nil
}

func (p *Prover[X, XV, W, WV, A, S, Z]) Round2(eCommitment *pedersen_comm.Commitment[XV, WV]) (A, error) {
	var zero A
	if p.round != 2 {
		return zero, errs.NewRound("r != 2 (%d)", p.round)
	}

	transcripts.Append(p.tape, challengeCommitmentLabel, eCommitment)

	p.challengeCommitment = eCommitment

	commitment, state, err := p.protocol.ComputeProverCommitment(p.statement, p.witness)
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot create commitment")
	}

	transcripts.Append(p.tape, commitmentLabel, commitment)
	p.commitment = commitment
	p.state = state
	p.round += 2
	return commitment, nil
}

func (p *Prover[X, XV, W, WV, A, S, Z]) Round4(challengeOpening *commitments.Opening[*pedersen_comm.Message, *pedersen_comm.Witness]) (Z, error) {
	var zero Z
	p.tape.AppendScalars(challengeLabel, challengeOpening.Message())

	if p.round != 4 {
		return zero, errs.NewRound("r != 4 (%d)", p.round)
	}
	if err := p.ck.Verify(p.challengeCommitment, challengeOpening.Message(), challengeOpening.Witness()); err != nil {
		return zero, errs.WrapVerification(err, "invalid challenge")
	}

	response, err := p.protocol.ComputeProverResponse(p.statement, p.witness, p.commitment, p.state, p.pedersenMessageToChallengeBytes(challengeOpening.Message()))
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot generate response")
	}
	p.tape.AppendMessages(responseLabel, p.protocol.SerializeResponse(response))

	p.response = response
	p.round += 2
	return response, nil
}
