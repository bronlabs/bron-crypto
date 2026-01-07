package sigor

import (
	"crypto/subtle"
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
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

type StateCartesian[S0, S1 sigma.State, Z0, Z1 sigma.Response] struct {
	B  uint
	S0 S0
	S1 S1
	E  []byte
	Z0 Z0
	Z1 Z1
}

var _ sigma.State = (*StateCartesian[sigma.State, sigma.State, sigma.Response, sigma.Response])(nil)

type ResponseCartesian[Z0, Z1 sigma.Response] struct {
	E0 []byte
	E1 []byte
	Z0 Z0
	Z1 Z1
}

func (r *ResponseCartesian[Z0, Z1]) Bytes() []byte {
	return slices.Concat(r.E0, r.E1, r.Z0.Bytes(), r.Z1.Bytes())
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
	prng                 io.Reader
}

func CartesianCompose[X0, X1 sigma.Statement, W0, W1 sigma.Witness, A0, A1 sigma.Commitment, S0, S1 sigma.State, Z0, Z1 sigma.Response](sigma0 sigma.Protocol[X0, W0, A0, S0, Z0], sigma1 sigma.Protocol[X1, W1, A1, S1, Z1], prng io.Reader) sigma.Protocol[*StatementCartesian[X0, X1], *WitnessCartesian[W0, W1], *CommitmentCartesian[A0, A1], *StateCartesian[S0, S1, Z0, Z1], *ResponseCartesian[Z0, Z1]] {
	challengeBytesLength := max(sigma0.GetChallengeBytesLength(), sigma1.GetChallengeBytesLength())

	return &protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]{
		sigma0:               sigma0,
		sigma1:               sigma1,
		challengeBytesLength: challengeBytesLength,
		prng:                 prng,
	}
}

func (p protocolCartesian[_, _, _, _, _, _, _, _, _, _]) SoundnessError() uint {
	return min(p.sigma0.SoundnessError(), p.sigma1.SoundnessError())
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ComputeProverCommitment(statement *StatementCartesian[X0, X1], witness *WitnessCartesian[W0, W1]) (*CommitmentCartesian[A0, A1], *StateCartesian[S0, S1, Z0, Z1], error) {
	var err error

	if statement == nil || witness == nil {
		return nil, nil, ErrIsNil.WithMessage("statement/commitment is nil")
	}

	a := new(CommitmentCartesian[A0, A1])
	s := new(StateCartesian[S0, S1, Z0, Z1])
	s.E = make([]byte, p.challengeBytesLength)
	_, err = io.ReadFull(p.prng, s.E)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot generate challenge")
	}

	if invalid := p.sigma0.ValidateStatement(statement.X0, witness.W0); invalid == nil {
		s.B = 0

		a.A0, s.S0, err = p.sigma0.ComputeProverCommitment(statement.X0, witness.W0)
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot compute commitment")
		}

		a.A1, s.Z1, err = p.sigma1.RunSimulator(statement.X1, s.E[:p.sigma1.GetChallengeBytesLength()])
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot run simulator")
		}
	} else {
		s.B = 1

		a.A1, s.S1, err = p.sigma1.ComputeProverCommitment(statement.X1, witness.W1)
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot compute commitment")
		}

		a.A0, s.Z0, err = p.sigma0.RunSimulator(statement.X0, s.E[:p.sigma0.GetChallengeBytesLength()])
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot run simulator")
		}
	}

	return a, s, nil
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ComputeProverResponse(statement *StatementCartesian[X0, X1], witness *WitnessCartesian[W0, W1], commitment *CommitmentCartesian[A0, A1], state *StateCartesian[S0, S1, Z0, Z1], challengeBytes sigma.ChallengeBytes) (*ResponseCartesian[Z0, Z1], error) {
	if statement == nil || witness == nil || commitment == nil || state == nil {
		return nil, ErrIsNil.WithMessage("statement/witness/commitment/statement is nil")
	}
	if len(challengeBytes) != p.challengeBytesLength {
		return nil, ErrInvalidLength.WithMessage("invalid challenge bytes length")
	}

	var err error
	z := new(ResponseCartesian[Z0, Z1])
	switch state.B {
	case 0:
		z.E0 = make([]byte, p.challengeBytesLength)
		subtle.XORBytes(z.E0, state.E, challengeBytes)
		z.Z0, err = p.sigma0.ComputeProverResponse(statement.X0, witness.W0, commitment.A0, state.S0, z.E0[:p.sigma0.GetChallengeBytesLength()])
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("cannot compute response")
		}

		z.E1 = state.E
		z.Z1 = state.Z1

	case 1:
		z.E1 = make([]byte, p.challengeBytesLength)
		subtle.XORBytes(z.E1, state.E, challengeBytes)
		z.Z1, err = p.sigma1.ComputeProverResponse(statement.X1, witness.W1, commitment.A1, state.S1, z.E1[:p.sigma1.GetChallengeBytesLength()])
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("cannot compute response")
		}

		z.E0 = state.E
		z.Z0 = state.Z0

	default:
		return nil, ErrInvalidArgument.WithMessage("invalid state")
	}

	return z, nil
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) Verify(statement *StatementCartesian[X0, X1], commitment *CommitmentCartesian[A0, A1], challengeBytes sigma.ChallengeBytes, response *ResponseCartesian[Z0, Z1]) error {
	if statement == nil || commitment == nil || response == nil {
		return ErrIsNil.WithMessage("statement/commitment/response is nil")
	}
	if len(challengeBytes) != p.challengeBytesLength {
		return ErrInvalidLength.WithMessage("invalid challenge bytes length")
	}

	e0XorE1 := make([]byte, p.challengeBytesLength)
	subtle.XORBytes(e0XorE1, response.E0, response.E1)
	if ct.SliceEqual(challengeBytes, e0XorE1) == ct.False {
		return ErrVerification.WithMessage("verification failed")
	}

	// check that conversation (a_0, e_0, z_0) are accepting in Protocol on input x_0
	if err := p.sigma0.Verify(statement.X0, commitment.A0, response.E0[:p.sigma0.GetChallengeBytesLength()], response.Z0); err != nil {
		return errs2.Wrap(err).WithMessage("verification failed")
	}

	// check that conversation (a_1, e_1, z_1) are accepting in Protocol on input x_1
	if err := p.sigma1.Verify(statement.X1, commitment.A1, response.E1[:p.sigma1.GetChallengeBytesLength()], response.Z1); err != nil {
		return errs2.Wrap(err).WithMessage("verification failed")
	}

	return nil
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) RunSimulator(statement *StatementCartesian[X0, X1], challengeBytes sigma.ChallengeBytes) (*CommitmentCartesian[A0, A1], *ResponseCartesian[Z0, Z1], error) {
	if statement == nil {
		return nil, nil, ErrIsNil.WithMessage("statement")
	}
	if len(challengeBytes) != p.challengeBytesLength {
		return nil, nil, ErrInvalidLength.WithMessage("challengeBytes")
	}

	a := new(CommitmentCartesian[A0, A1])
	z := new(ResponseCartesian[Z0, Z1])

	z.E0 = make([]byte, p.challengeBytesLength)
	_, err := io.ReadFull(p.prng, z.E0)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("prng failed")
	}
	z.E1 = make([]byte, p.challengeBytesLength)
	subtle.XORBytes(z.E1, challengeBytes, z.E0)

	a.A0, z.Z0, err = p.sigma0.RunSimulator(statement.X0, z.E0)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot run simulator")
	}
	a.A1, z.Z1, err = p.sigma1.RunSimulator(statement.X1, z.E1)
	if err != nil {
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

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ValidateStatement(statement *StatementCartesian[X0, X1], witness *WitnessCartesian[W0, W1]) error {
	err0 := p.sigma0.ValidateStatement(statement.X0, witness.W0)
	err1 := p.sigma1.ValidateStatement(statement.X1, witness.W1)

	if err0 != nil && err1 != nil {
		return ErrNotExactlyOneOutOfN.WithStackFrame()
	}

	return nil
}

func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) Name() sigma.Name {
	return sigma.Name(fmt.Sprintf("(%s)_OR_(%s)", p.sigma0.Name(), p.sigma1.Name()))
}
