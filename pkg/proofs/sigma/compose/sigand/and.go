package sigand

import (
	"fmt"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

type Statement[X0, X1 sigma.Statement] struct {
	X0 X0
	X1 X1
}

var _ sigma.Statement = (*Statement[sigma.Statement, sigma.Statement])(nil)

type Witness[W0, W1 sigma.Witness] struct {
	W0 W0
	W1 W1
}

var _ sigma.Witness = (*Witness[sigma.Witness, sigma.Witness])(nil)

type Commitment[A0, A1 sigma.Commitment] struct {
	A0 A0
	A1 A1
}

var _ sigma.Commitment = (*Commitment[sigma.Commitment, sigma.Commitment])(nil)

type State[S0, S1 sigma.State] struct {
	S0 S0
	S1 S1
}

var _ sigma.State = (*State[sigma.State, sigma.State])(nil)

type Response[Z0, Z1 sigma.Response] struct {
	Z0 Z0
	Z1 Z1
}

var _ sigma.Response = (*Response[sigma.Response, sigma.Response])(nil)

func StatementAnd[X0, X1 sigma.Statement](statement0 X0, statement1 X1) *Statement[X0, X1] {
	return &Statement[X0, X1]{
		X0: statement0,
		X1: statement1,
	}
}

func WitnessAnd[W0, W1 sigma.Witness](witness0 W0, witness1 W1) *Witness[W0, W1] {
	return &Witness[W0, W1]{
		W0: witness0,
		W1: witness1,
	}
}

type protocol[X0, X1 sigma.Statement, W0, W1 sigma.Witness, A0, A1 sigma.Commitment, S0, S1 sigma.State, Z0, Z1 sigma.Response] struct {
	sigma0               sigma.Protocol[X0, W0, A0, S0, Z0]
	sigma1               sigma.Protocol[X1, W1, A1, S1, Z1]
	challengeBytesLength int
}

func SigmaAnd[X0, X1 sigma.Statement, W0, W1 sigma.Witness, A0, A1 sigma.Commitment, S0, S1 sigma.State, Z0, Z1 sigma.Response](sigma0 sigma.Protocol[X0, W0, A0, S0, Z0], sigma1 sigma.Protocol[X1, W1, A1, S1, Z1]) sigma.Protocol[*Statement[X0, X1], *Witness[W0, W1], *Commitment[A0, A1], *State[S0, S1], *Response[Z0, Z1]] {
	challengeBytesLength := max(sigma0.GetChallengeBytesLength(), sigma1.GetChallengeBytesLength())

	return &protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]{
		sigma0:               sigma0,
		sigma1:               sigma1,
		challengeBytesLength: challengeBytesLength,
	}
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ComputeProverCommitment(statement *Statement[X0, X1], witness *Witness[W0, W1]) (*Commitment[A0, A1], *State[S0, S1], error) {
	var err error
	a := new(Commitment[A0, A1])
	s := new(State[S0, S1])

	if a.A0, s.S0, err = p.sigma0.ComputeProverCommitment(statement.X0, witness.W0); err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute commitment")
	}
	if a.A1, s.S1, err = p.sigma1.ComputeProverCommitment(statement.X1, witness.W1); err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute commitment")
	}

	return a, s, nil
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ComputeProverResponse(statement *Statement[X0, X1], witness *Witness[W0, W1], commitment *Commitment[A0, A1], state *State[S0, S1], challengeBytes sigma.ChallengeBytes) (*Response[Z0, Z1], error) {
	var err error
	z := new(Response[Z0, Z1])

	if z.Z0, err = p.sigma0.ComputeProverResponse(statement.X0, witness.W0, commitment.A0, state.S0, challengeBytes[:p.sigma0.GetChallengeBytesLength()]); err != nil {
		return nil, errs.WrapFailed(err, "cannot compute response")
	}
	if z.Z1, err = p.sigma1.ComputeProverResponse(statement.X1, witness.W1, commitment.A1, state.S1, challengeBytes[:p.sigma1.GetChallengeBytesLength()]); err != nil {
		return nil, errs.WrapFailed(err, "cannot compute response")
	}

	return z, nil
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) Verify(statement *Statement[X0, X1], commitment *Commitment[A0, A1], challengeBytes sigma.ChallengeBytes, response *Response[Z0, Z1]) error {
	if err := p.sigma0.Verify(statement.X0, commitment.A0, challengeBytes[:p.sigma0.GetChallengeBytesLength()], response.Z0); err != nil {
		return errs.WrapVerification(err, "verification failed")
	}
	if err := p.sigma1.Verify(statement.X1, commitment.A1, challengeBytes[:p.sigma1.GetChallengeBytesLength()], response.Z1); err != nil {
		return errs.WrapVerification(err, "verification failed")
	}

	return nil
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) RunSimulator(statement *Statement[X0, X1], challengeBytes sigma.ChallengeBytes) (*Commitment[A0, A1], *Response[Z0, Z1], error) {
	var err error
	a := new(Commitment[A0, A1])
	z := new(Response[Z0, Z1])

	if a.A0, z.Z0, err = p.sigma0.RunSimulator(statement.X0, challengeBytes[:p.sigma0.GetChallengeBytesLength()]); err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run simulator")
	}
	if a.A1, z.Z1, err = p.sigma1.RunSimulator(statement.X1, challengeBytes[:p.sigma1.GetChallengeBytesLength()]); err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run simulator")
	}

	return a, z, nil
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) GetChallengeBytesLength() int {
	return p.challengeBytesLength
}

func (p protocol[_, _, _, _, _, _, _, _, _, _]) SoundnessError() int {
	return min(p.sigma0.SoundnessError(), p.sigma1.SoundnessError())
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ValidateStatement(statement *Statement[X0, X1], witness *Witness[W0, W1]) error {
	if err := p.sigma0.ValidateStatement(statement.X0, witness.W0); err != nil {
		return errs.WrapValidation(err, "invalid statement")
	}
	if err := p.sigma1.ValidateStatement(statement.X1, witness.W1); err != nil {
		return errs.WrapValidation(err, "invalid statement")
	}

	return nil
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) SerializeStatement(statement *Statement[X0, X1]) []byte {
	return slices.Concat(p.sigma0.SerializeStatement(statement.X0), p.sigma1.SerializeStatement(statement.X1))
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) SerializeCommitment(commitment *Commitment[A0, A1]) []byte {
	return slices.Concat(p.sigma0.SerializeCommitment(commitment.A0), p.sigma1.SerializeCommitment(commitment.A1))
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) SerializeResponse(response *Response[Z0, Z1]) []byte {
	return slices.Concat(p.sigma0.SerializeResponse(response.Z0), p.sigma1.SerializeResponse(response.Z1))
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) Name() sigma.Name {
	return sigma.Name(fmt.Sprintf("(%s)_AND_(%s)", p.sigma0.Name(), p.sigma1.Name()))
}
