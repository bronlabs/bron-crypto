package sigand

import (
	"fmt"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

type StatementCartesian[X0, X1 sigma.Statement] struct {
	X0 X0
	X1 X1
}

func (s *StatementCartesian[X0, X1]) Bytes() []byte {
	return slices.Concat(s.X0.Bytes(), s.X1.Bytes())
}

var _ sigma.Statement = (*StatementCartesian[sigma.Statement, sigma.Statement])(nil)

type WitnessCartesian[W0, W1 sigma.Witness] struct {
	W0 W0
	W1 W1
}

func (w *WitnessCartesian[W0, W1]) Bytes() []byte {
	return slices.Concat(w.W0.Bytes(), w.W1.Bytes())
}

var _ sigma.Witness = (*WitnessCartesian[sigma.Witness, sigma.Witness])(nil)

type CommitmentCartesian[A0, A1 sigma.Commitment] struct {
	A0 A0
	A1 A1
}

func (c *CommitmentCartesian[A0, A1]) Bytes() []byte {
	return slices.Concat(c.A0.Bytes(), c.A1.Bytes())
}

var _ sigma.Commitment = (*CommitmentCartesian[sigma.Commitment, sigma.Commitment])(nil)

type StateCartesian[S0, S1 sigma.State] struct {
	S0 S0
	S1 S1
}

var _ sigma.State = (*StateCartesian[sigma.State, sigma.State])(nil)

type ResponseCartesian[Z0, Z1 sigma.Response] struct {
	Z0 Z0
	Z1 Z1
}

func (r *ResponseCartesian[Z0, Z1]) Bytes() []byte {
	return slices.Concat(r.Z0.Bytes(), r.Z1.Bytes())
}

var _ sigma.Response = (*ResponseCartesian[sigma.Response, sigma.Response])(nil)

func CartesianComposeStatements[X0, X1 sigma.Statement](statement0 X0, statement1 X1) *StatementCartesian[X0, X1] {
	return &StatementCartesian[X0, X1]{
		X0: statement0,
		X1: statement1,
	}
}

func CartesianComposeWitnesses[W0, W1 sigma.Witness](witness0 W0, witness1 W1) *WitnessCartesian[W0, W1] {
	return &WitnessCartesian[W0, W1]{
		W0: witness0,
		W1: witness1,
	}
}

type protocolCartesian[X0, X1 sigma.Statement, W0, W1 sigma.Witness, A0, A1 sigma.Commitment, S0, S1 sigma.State, Z0, Z1 sigma.Response] struct {
	sigma0               sigma.Protocol[X0, W0, A0, S0, Z0]
	sigma1               sigma.Protocol[X1, W1, A1, S1, Z1]
	challengeBytesLength int
}

func CartesianCompose[X0, X1 sigma.Statement, W0, W1 sigma.Witness, A0, A1 sigma.Commitment, S0, S1 sigma.State, Z0, Z1 sigma.Response](sigma0 sigma.Protocol[X0, W0, A0, S0, Z0], sigma1 sigma.Protocol[X1, W1, A1, S1, Z1]) sigma.Protocol[*StatementCartesian[X0, X1], *WitnessCartesian[W0, W1], *CommitmentCartesian[A0, A1], *StateCartesian[S0, S1], *ResponseCartesian[Z0, Z1]] {
	challengeBytesLength := max(sigma0.GetChallengeBytesLength(), sigma1.GetChallengeBytesLength())

	return &protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]{
		sigma0:               sigma0,
		sigma1:               sigma1,
		challengeBytesLength: challengeBytesLength,
	}
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ComputeProverCommitment(statement *StatementCartesian[X0, X1], witness *WitnessCartesian[W0, W1]) (*CommitmentCartesian[A0, A1], *StateCartesian[S0, S1], error) {
	var err error
	a := new(CommitmentCartesian[A0, A1])
	s := new(StateCartesian[S0, S1])

	if a.A0, s.S0, err = p.sigma0.ComputeProverCommitment(statement.X0, witness.W0); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot compute commitment")
	}
	if a.A1, s.S1, err = p.sigma1.ComputeProverCommitment(statement.X1, witness.W1); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot compute commitment")
	}

	return a, s, nil
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ComputeProverResponse(statement *StatementCartesian[X0, X1], witness *WitnessCartesian[W0, W1], commitment *CommitmentCartesian[A0, A1], state *StateCartesian[S0, S1], challengeBytes sigma.ChallengeBytes) (*ResponseCartesian[Z0, Z1], error) {
	var err error
	z := new(ResponseCartesian[Z0, Z1])

	if z.Z0, err = p.sigma0.ComputeProverResponse(statement.X0, witness.W0, commitment.A0, state.S0, challengeBytes[:p.sigma0.GetChallengeBytesLength()]); err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot compute response")
	}
	if z.Z1, err = p.sigma1.ComputeProverResponse(statement.X1, witness.W1, commitment.A1, state.S1, challengeBytes[:p.sigma1.GetChallengeBytesLength()]); err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot compute response")
	}

	return z, nil
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) Verify(statement *StatementCartesian[X0, X1], commitment *CommitmentCartesian[A0, A1], challengeBytes sigma.ChallengeBytes, response *ResponseCartesian[Z0, Z1]) error {
	if err := p.sigma0.Verify(statement.X0, commitment.A0, challengeBytes[:p.sigma0.GetChallengeBytesLength()], response.Z0); err != nil {
		return errs2.Wrap(err).WithMessage("verification failed")
	}
	if err := p.sigma1.Verify(statement.X1, commitment.A1, challengeBytes[:p.sigma1.GetChallengeBytesLength()], response.Z1); err != nil {
		return errs2.Wrap(err).WithMessage("verification failed")
	}

	return nil
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) RunSimulator(statement *StatementCartesian[X0, X1], challengeBytes sigma.ChallengeBytes) (*CommitmentCartesian[A0, A1], *ResponseCartesian[Z0, Z1], error) {
	var err error
	a := new(CommitmentCartesian[A0, A1])
	z := new(ResponseCartesian[Z0, Z1])

	if a.A0, z.Z0, err = p.sigma0.RunSimulator(statement.X0, challengeBytes[:p.sigma0.GetChallengeBytesLength()]); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot run simulator")
	}
	if a.A1, z.Z1, err = p.sigma1.RunSimulator(statement.X1, challengeBytes[:p.sigma1.GetChallengeBytesLength()]); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot run simulator")
	}

	return a, z, nil
}

func (p *protocolCartesian[_, _, _, _, _, _, _, _, _, _]) SpecialSoundness() uint {
	return max(p.sigma0.SpecialSoundness(), p.sigma1.SpecialSoundness())
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) GetChallengeBytesLength() int {
	return p.challengeBytesLength
}

func (p protocolCartesian[_, _, _, _, _, _, _, _, _, _]) SoundnessError() uint {
	return min(p.sigma0.SoundnessError(), p.sigma1.SoundnessError())
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ValidateStatement(statement *StatementCartesian[X0, X1], witness *WitnessCartesian[W0, W1]) error {
	if err := p.sigma0.ValidateStatement(statement.X0, witness.W0); err != nil {
		return errs2.Wrap(err).WithMessage("invalid statement")
	}
	if err := p.sigma1.ValidateStatement(statement.X1, witness.W1); err != nil {
		return errs2.Wrap(err).WithMessage("invalid statement")
	}

	return nil
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) Name() sigma.Name {
	return sigma.Name(fmt.Sprintf("(%s)_AND_(%s)", p.sigma0.Name(), p.sigma1.Name()))
}
