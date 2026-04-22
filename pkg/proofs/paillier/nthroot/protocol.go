package nthroot

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Name identifies the Paillier nth-root sigma protocol.
const Name sigma.Name = "PAILLIER_NTH_ROOTS"

type (
	// Witness is the nth-root protocol witness.
	Witness[A znstar.ArithmeticPaillier] = maurer09.Witness[*znstar.PaillierGroupElement[A]]
	// Statement is the nth-root protocol statement.
	Statement[A znstar.ArithmeticPaillier] = maurer09.Statement[*znstar.PaillierGroupElement[A]]
	// State is the nth-root protocol prover state.
	State[A znstar.ArithmeticPaillier] = maurer09.State[*znstar.PaillierGroupElement[A]]
	// Commitment is the nth-root protocol commitment.
	Commitment[A znstar.ArithmeticPaillier] = maurer09.Commitment[*znstar.PaillierGroupElement[A]]
	// Response is the nth-root protocol response.
	Response[A znstar.ArithmeticPaillier] = maurer09.Response[*znstar.PaillierGroupElement[A]]
)

// NewStatement builds a new nth-root statement.
func NewStatement[X znstar.ArithmeticPaillier](x *znstar.PaillierGroupElement[X]) (*Statement[X], error) {
	if x == nil {
		return nil, ErrInvalidArgument.WithMessage("statement element must not be nil")
	}
	return &Statement[X]{
		X: x,
	}, nil
}

// NewWitness builds a new nth-root witness.
func NewWitness[X znstar.ArithmeticPaillier](w *znstar.PaillierGroupElement[X]) (*Witness[X], error) {
	if w == nil {
		return nil, ErrInvalidArgument.WithMessage("witness element must not be nil")
	}
	return &Witness[X]{
		W: w,
	}, nil
}

// Protocol implements the Paillier nth-root sigma protocol.
type Protocol[A znstar.ArithmeticPaillier] struct {
	maurer09.Protocol[*znstar.PaillierGroupElement[A], *znstar.PaillierGroupElement[A]]
}

// NewProtocol constructs a Paillier nth-root protocol instance.
func NewProtocol[A znstar.ArithmeticPaillier](group *znstar.PaillierGroup[A], prng io.Reader) (*Protocol[A], error) {
	if group == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("group or prng must not be nil")
	}
	oneWayHomomorphism := func(x *znstar.PaillierGroupElement[A]) (*znstar.PaillierGroupElement[A], error) {
		if x == nil {
			return nil, ErrInvalidArgument.WithMessage("homomorphism input cannot be nil")
		}
		y, err := group.NthResidue(x.ForgetOrder())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot compute nth residue")
		}
		return y, nil
	}
	anc := &anchor[A]{
		n: group.N().Nat(),
	}
	challengeBitLen := 128
	challengeByteLen := (challengeBitLen + 7) / 8
	soundnessError := uint(challengeBitLen)
	scalarMul := func(unit *znstar.PaillierGroupElement[A], eBytes []byte) (*znstar.PaillierGroupElement[A], error) {
		e, err := num.N().FromBytes(eBytes)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot convert bytes to scalar")
		}
		return unit.Exp(e), nil
	}

	proto, err := maurer09.NewProtocol(
		challengeByteLen,
		soundnessError,
		Name,
		group,
		group,
		oneWayHomomorphism,
		anc,
		prng,
		maurer09.WithImageScalarMul[*znstar.PaillierGroupElement[A], *znstar.PaillierGroupElement[A]](scalarMul),
		maurer09.WithPreImageScalarMul[*znstar.PaillierGroupElement[A]](scalarMul),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create underlying Maurer09 protocol")
	}
	return &Protocol[A]{*proto}, nil
}

type anchor[A znstar.ArithmeticPaillier] struct {
	n *num.Nat
}

func (a *anchor[A]) L() *num.Nat {
	return a.n
}

func (*anchor[A]) PreImage(x *znstar.PaillierGroupElement[A]) (w *znstar.PaillierGroupElement[A]) {
	return x
}
