package sigmaOr

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
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

type State[S0, S1 sigma.State, Z0, Z1 sigma.Response] struct {
	B  uint
	S0 S0
	S1 S1
	E  []byte
	Z0 Z0
	Z1 Z1
}

var _ sigma.State = (*State[sigma.State, sigma.State, sigma.Response, sigma.Response])(nil)

type Response[Z0, Z1 sigma.Response] struct {
	E0 []byte
	E1 []byte
	Z0 Z0
	Z1 Z1
}

var _ sigma.Response = (*Response[sigma.Response, sigma.Response])(nil)

func StatementOr[X0, X1 sigma.Statement](statement0 X0, statement1 X1) *Statement[X0, X1] {
	return &Statement[X0, X1]{
		X0: statement0,
		X1: statement1,
	}
}

func WitnessOr[W0, W1 sigma.Witness](witness0 W0, witness1 W1) *Witness[W0, W1] {
	return &Witness[W0, W1]{
		W0: witness0,
		W1: witness1,
	}
}

type protocol[X0, X1 sigma.Statement, W0, W1 sigma.Witness, A0, A1 sigma.Commitment, S0, S1 sigma.State, Z0, Z1 sigma.Response] struct {
	sigma0               sigma.Protocol[X0, W0, A0, S0, Z0]
	sigma1               sigma.Protocol[X1, W1, A1, S1, Z1]
	challengeBytesLength int
	prng                 io.Reader
}

func SigmaOr[X0, X1 sigma.Statement, W0, W1 sigma.Witness, A0, A1 sigma.Commitment, S0, S1 sigma.State, Z0, Z1 sigma.Response](sigma0 sigma.Protocol[X0, W0, A0, S0, Z0], sigma1 sigma.Protocol[X1, W1, A1, S1, Z1], prng io.Reader) sigma.Protocol[*Statement[X0, X1], *Witness[W0, W1], *Commitment[A0, A1], *State[S0, S1, Z0, Z1], *Response[Z0, Z1]] {
	challengeBytesLength := utils.Max(sigma0.GetChallengeBytesLength(), sigma1.GetChallengeBytesLength())

	return &protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]{
		sigma0:               sigma0,
		sigma1:               sigma1,
		challengeBytesLength: challengeBytesLength,
		prng:                 prng,
	}
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ComputeProverCommitment(statement *Statement[X0, X1], witness *Witness[W0, W1]) (*Commitment[A0, A1], *State[S0, S1, Z0, Z1], error) {
	var err error

	if statement == nil || witness == nil {
		return nil, nil, errs.NewIsNil("statement/commitment is nil")
	}

	a := new(Commitment[A0, A1])
	s := new(State[S0, S1, Z0, Z1])
	if invalid := p.sigma0.ValidateStatement(statement.X0, witness.W0); invalid == nil {
		s.B = 0

		a.A0, s.S0, err = p.sigma0.ComputeProverCommitment(statement.X0, witness.W0)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot compute commitment")
		}

		s.E = make([]byte, p.challengeBytesLength)
		_, err = io.ReadFull(p.prng, s.E)
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "cannot generate challenge")
		}

		a.A1, s.Z1, err = p.sigma1.RunSimulator(statement.X1, s.E[:p.sigma1.GetChallengeBytesLength()])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run simulator")
		}
	} else {
		s.B = 1

		a.A1, s.S1, err = p.sigma1.ComputeProverCommitment(statement.X1, witness.W1)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot compute commitment")
		}

		s.E = make([]byte, p.challengeBytesLength)
		_, err = io.ReadFull(p.prng, s.E)
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "cannot sample challenge")
		}
		a.A0, s.Z0, err = p.sigma0.RunSimulator(statement.X0, s.E[:p.sigma0.GetChallengeBytesLength()])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run simulator")
		}
	}

	return a, s, nil
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ComputeProverResponse(statement *Statement[X0, X1], witness *Witness[W0, W1], commitment *Commitment[A0, A1], state *State[S0, S1, Z0, Z1], challengeBytes []byte) (*Response[Z0, Z1], error) {
	if statement == nil || witness == nil || commitment == nil || state == nil {
		return nil, errs.NewIsNil("statement/witness/commitment/statement is nil")
	}
	if len(challengeBytes) != p.challengeBytesLength {
		return nil, errs.NewLength("invalid challenge bytes length")
	}

	e := make([]byte, p.challengeBytesLength)
	_, err := io.ReadFull(p.prng, e)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate challenge")
	}

	z := new(Response[Z0, Z1])
	switch state.B {
	case 0:
		z.E0 = make([]byte, p.challengeBytesLength)
		subtle.XORBytes(z.E0, state.E, challengeBytes)
		z.Z0, err = p.sigma0.ComputeProverResponse(statement.X0, witness.W0, commitment.A0, state.S0, z.E0[:p.sigma0.GetChallengeBytesLength()])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot compute response")
		}

		z.E1 = state.E
		z.Z1 = state.Z1

	case 1:
		z.E1 = make([]byte, p.challengeBytesLength)
		subtle.XORBytes(z.E1, state.E, challengeBytes)
		z.Z1, err = p.sigma1.ComputeProverResponse(statement.X1, witness.W1, commitment.A1, state.S1, z.E1[:p.sigma1.GetChallengeBytesLength()])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot compute response")
		}

		z.E0 = state.E
		z.Z0 = state.Z0

	default:
		return nil, errs.NewArgument("invalid state")
	}

	return z, nil
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) Verify(statement *Statement[X0, X1], commitment *Commitment[A0, A1], challengeBytes []byte, response *Response[Z0, Z1]) error {
	if statement == nil || commitment == nil || response == nil {
		return errs.NewIsNil("statement/commitment/response is nil")
	}
	if len(challengeBytes) != p.challengeBytesLength {
		return errs.NewLength("invalid challenge bytes length")
	}

	e0XorE1 := make([]byte, p.challengeBytesLength)
	subtle.XORBytes(e0XorE1, response.E0, response.E1)
	if !bytes.Equal(challengeBytes, e0XorE1) {
		return errs.NewVerification("verification failed")
	}

	// check that conversation (a_0, e_0, z_0) are accepting in Protocol on input x_0
	if err := p.sigma0.Verify(statement.X0, commitment.A0, response.E0[:p.sigma0.GetChallengeBytesLength()], response.Z0); err != nil {
		return errs.NewVerification("verification failed")
	}

	// check that conversation (a_1, e_1, z_1) are accepting in Protocol on input x_1
	if err := p.sigma1.Verify(statement.X1, commitment.A1, response.E1[:p.sigma1.GetChallengeBytesLength()], response.Z1); err != nil {
		return errs.NewVerification("verification failed")
	}

	return nil
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) RunSimulator(statement *Statement[X0, X1], challengeBytes []byte) (*Commitment[A0, A1], *Response[Z0, Z1], error) {
	if statement == nil {
		return nil, nil, errs.NewIsNil("statement")
	}
	if len(challengeBytes) != p.challengeBytesLength {
		return nil, nil, errs.NewLength("challengeBytes")
	}

	a := new(Commitment[A0, A1])
	z := new(Response[Z0, Z1])

	z.E0 = make([]byte, p.challengeBytesLength)
	_, err := io.ReadFull(p.prng, z.E0)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "prng failed")
	}
	z.E1 = make([]byte, p.challengeBytesLength)
	subtle.XORBytes(z.E1, challengeBytes, z.E0)

	a.A0, z.Z0, err = p.sigma0.RunSimulator(statement.X0, z.E0)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run simulator")
	}
	a.A1, z.Z1, err = p.sigma1.RunSimulator(statement.X1, z.E1)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run simulator")
	}

	return a, z, nil
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) GetChallengeBytesLength() int {
	return p.challengeBytesLength
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ValidateStatement(statement *Statement[X0, X1], witness *Witness[W0, W1]) error {
	err0 := p.sigma0.ValidateStatement(statement.X0, witness.W0)
	err1 := p.sigma1.ValidateStatement(statement.X1, witness.W1)

	if err0 != nil && err1 != nil {
		return errs.NewFailed("invalid statement")
	}

	return nil
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) SerializeStatement(statement *Statement[X0, X1]) []byte {
	return bytes.Join([][]byte{p.sigma0.SerializeStatement(statement.X0), p.sigma1.SerializeStatement(statement.X1)}, nil)
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) SerializeCommitment(commitment *Commitment[A0, A1]) []byte {
	return bytes.Join([][]byte{p.sigma0.SerializeCommitment(commitment.A0), p.sigma1.SerializeCommitment(commitment.A1)}, nil)
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) SerializeResponse(response *Response[Z0, Z1]) []byte {
	return bytes.Join([][]byte{p.sigma0.SerializeResponse(response.Z0), p.sigma1.SerializeResponse(response.Z1)}, nil)
}

func (p protocol[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) Name() sigma.Name {
	return sigma.Name(fmt.Sprintf("(%s)_OR_(%s)", p.sigma0.Name(), p.sigma1.Name()))
}
