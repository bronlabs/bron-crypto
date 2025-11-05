package nthroots

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
	ScalarGroup[X znstar.ArithmeticPaillier]  = znstar.PaillierGroup[X]
	Scalar[X znstar.ArithmeticPaillier]       = znstar.PaillierGroupElement[X]
	Group[X znstar.ArithmeticPaillier]        = znstar.PaillierGroup[X]
	GroupElement[X znstar.ArithmeticPaillier] = znstar.PaillierGroupElement[X]
	Challenge                                 = num.Nat
)

var ChallengeSpace = num.N

type (
	Statement[X znstar.ArithmeticPaillier]  = maurer09.Statement[*Scalar[X], *GroupElement[X]]
	Witness[X znstar.ArithmeticPaillier]    = maurer09.Witness[*Scalar[X]]
	Commitment[X znstar.ArithmeticPaillier] = maurer09.Commitment[*Scalar[X], *GroupElement[X]]
	State[X znstar.ArithmeticPaillier]      = maurer09.State[*Scalar[X]]
	Response[X znstar.ArithmeticPaillier]   = maurer09.Response[*Scalar[X]]
)

func NewStatementKnownOrder(x *GroupElement[*modular.SimpleModulus], g *znstar.PaillierGroupKnownOrder) (*Statement[*modular.OddPrimeSquareFactors], error) {
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

func NewStatement[X znstar.ArithmeticPaillier](x *GroupElement[X]) *Statement[X] {
	return &Statement[X]{
		X: x,
	}
}

func NewWitnessKnownOrder[X znstar.ArithmeticPaillier](w *Scalar[*modular.SimpleModulus], g *znstar.PaillierGroupKnownOrder) (*Witness[*modular.OddPrimeSquareFactors], error) {
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

func NewWitness[X znstar.ArithmeticPaillier](w *Scalar[X]) *Witness[X] {
	return &Witness[X]{
		W: w,
	}
}

func NewCommitmentKnownOrder(c *GroupElement[*modular.SimpleModulus], g *znstar.PaillierGroupKnownOrder) (*Commitment[*modular.OddPrimeSquareFactors], error) {
	if c == nil || g == nil {
		return nil, errs.NewIsNil("c or g")
	}
	learnedC, err := c.LearnOrder(g)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to learn order of c")
	}
	return &Commitment[*modular.OddPrimeSquareFactors]{
		C: learnedC,
	}, nil
}

func NewCommitment[X znstar.ArithmeticPaillier](c *GroupElement[X]) *Commitment[X] {
	return &Commitment[X]{
		C: c,
	}
}

func NewResponseKnownOrder(r *Scalar[*modular.SimpleModulus], g *znstar.PaillierGroupKnownOrder) (*Response[*modular.OddPrimeSquareFactors], error) {
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

func NewResponse[X znstar.ArithmeticPaillier](r *Scalar[X]) *Response[X] {
	return &Response[X]{
		Z: r,
	}
}

func Phi[X znstar.ArithmeticPaillier](g *ScalarGroup[X]) maurer09.GroupHomomorphism[*Scalar[X], *GroupElement[X]] {
	return func(s *Scalar[X]) *GroupElement[X] {
		out, err := g.NthResidue(s.ForgetOrder())
		if err != nil {
			panic(err)
		}
		return out
	}
}

func ChallengeActionOnPreImage[X znstar.ArithmeticPaillier](c *Challenge, x *Scalar[X]) *Scalar[X] {
	return x.ScalarExp(c)
}

func ChallengeActionOnImage[X znstar.ArithmeticPaillier](c *Challenge, x *GroupElement[X]) *GroupElement[X] {
	return x.Exp(c)
}

type Protocol[X znstar.ArithmeticPaillier] struct {
	maurer09.Protocol[*Scalar[X], *GroupElement[X], *Challenge, *ScalarGroup[X], *Group[X]]
}

func NewSigmaProtocol[X znstar.ArithmeticPaillier](g *znstar.PaillierGroup[X], prng io.Reader) (sigma.Protocol[*Statement[X], *Witness[X], *Commitment[X], *State[X], *Response[X]], error) {
	if prng == nil || g == nil {
		return nil, errs.NewIsNil("g or prng")
	}

	hom := Phi(g)
	subProtocol, err := maurer09.NewProtocol(hom, g, g, ChallengeSpace(), ChallengeActionOnPreImage, ChallengeActionOnImage, g.Random, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create underlying Maurer09 protocol")
	}
	return &Protocol[X]{
		Protocol: *subProtocol,
	}, nil
}

func (p *Protocol[X]) Name() sigma.Name {
	return Name
}
