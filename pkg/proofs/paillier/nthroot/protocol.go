package nthroot

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name sigma.Name = "PAILLIER_NTH_ROOTS"

type (
	Witness[A znstar.ArithmeticPaillier]    = maurer09.Witness[*znstar.PaillierGroupElement[A]]
	Statement[A znstar.ArithmeticPaillier]  = maurer09.Statement[*znstar.PaillierGroupElement[A]]
	State[A znstar.ArithmeticPaillier]      = maurer09.State[*znstar.PaillierGroupElement[A]]
	Commitment[A znstar.ArithmeticPaillier] = maurer09.Commitment[*znstar.PaillierGroupElement[A]]
	Response[A znstar.ArithmeticPaillier]   = maurer09.Response[*znstar.PaillierGroupElement[A]]
)

func NewStatementKnownOrder(x *znstar.PaillierGroupElement[*modular.SimpleModulus], g *znstar.PaillierGroupKnownOrder) (*Statement[*modular.OddPrimeSquareFactors], error) {
	if x == nil || g == nil {
		return nil, errs.NewIsNil("x or g")
	}
	learnedX, err := x.LearnOrder(g)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to learn order of x")
	}
	return &Statement[*modular.OddPrimeSquareFactors]{
		X: learnedX,
	}, nil
}

func NewStatement[X znstar.ArithmeticPaillier](x *znstar.PaillierGroupElement[X]) *Statement[X] {
	return &Statement[X]{
		X: x,
	}
}

func NewWitnessKnownOrder[X znstar.ArithmeticPaillier](w *znstar.PaillierGroupElement[*modular.SimpleModulus], g *znstar.PaillierGroupKnownOrder) (*Witness[*modular.OddPrimeSquareFactors], error) {
	if w == nil || g == nil {
		return nil, errs.NewIsNil("w or g")
	}
	learnedW, err := w.LearnOrder(g)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to learn order of w")
	}
	return &Witness[*modular.OddPrimeSquareFactors]{
		W: learnedW,
	}, nil
}

func NewWitness[X znstar.ArithmeticPaillier](w *znstar.PaillierGroupElement[X]) *Witness[X] {
	return &Witness[X]{
		W: w,
	}
}

func NewCommitmentKnownOrder(c *znstar.PaillierGroupElement[*modular.SimpleModulus], g *znstar.PaillierGroupKnownOrder) (*Commitment[*modular.OddPrimeSquareFactors], error) {
	if c == nil || g == nil {
		return nil, errs.NewIsNil("c or g")
	}
	learnedA, err := c.LearnOrder(g)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to learn order of c")
	}
	return &Commitment[*modular.OddPrimeSquareFactors]{
		A: learnedA,
	}, nil
}

func NewCommitment[X znstar.ArithmeticPaillier](a *znstar.PaillierGroupElement[X]) *Commitment[X] {
	return &Commitment[X]{
		A: a,
	}
}

func NewResponseKnownOrder(r *znstar.PaillierGroupElement[*modular.SimpleModulus], g *znstar.PaillierGroupKnownOrder) (*Response[*modular.OddPrimeSquareFactors], error) {
	if r == nil || g == nil {
		return nil, errs.NewIsNil("r or g")
	}
	learnedR, err := r.LearnOrder(g)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to learn order of r")
	}
	return &Response[*modular.OddPrimeSquareFactors]{
		Z: learnedR,
	}, nil
}

func NewResponse[X znstar.ArithmeticPaillier](r *znstar.PaillierGroupElement[X]) *Response[X] {
	return &Response[X]{
		Z: r,
	}
}

type Protocol[A znstar.ArithmeticPaillier] struct {
	maurer09.Protocol[*znstar.PaillierGroupElement[A], *znstar.PaillierGroupElement[A]]
}

func NewProtocol[A znstar.ArithmeticPaillier](group *znstar.PaillierGroup[A], prng io.Reader) (*Protocol[A], error) {
	oneWayHomomorphism := func(x *znstar.PaillierGroupElement[A]) *znstar.PaillierGroupElement[A] {
		y, _ := group.NthResidue(x.ForgetOrder())
		return y
	}
	anc := &anchor[A]{
		n: group.N().Nat(),
	}
	challengeBitLen := 128
	challengeByteLen := (challengeBitLen + 7) / 8
	soundnessError := uint(challengeBitLen)
	scalarMul := func(unit *znstar.PaillierGroupElement[A], eBytes []byte) *znstar.PaillierGroupElement[A] {
		e, _ := num.N().FromBytes(eBytes)
		return unit.Exp(e)
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
		maurer09.WithPreImageScalarMul[*znstar.PaillierGroupElement[A], *znstar.PaillierGroupElement[A]](scalarMul),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create underlying Maurer09 protocol")
	}
	return &Protocol[A]{*proto}, nil
}

type anchor[A znstar.ArithmeticPaillier] struct {
	n *num.Nat
}

func (a *anchor[A]) L() *num.Nat {
	return a.n
}

func (a *anchor[A]) PreImage(x *znstar.PaillierGroupElement[A]) (w *znstar.PaillierGroupElement[A]) {
	return x
}
