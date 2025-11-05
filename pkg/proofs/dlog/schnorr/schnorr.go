package schnorr

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name sigma.Name = "SCHNORR" + dlog.Type

type (
	ScalarField[S Scalar[S]] interface {
		maurer09.PreImageGroup[S]
		algebra.PrimeField[S]
	}
	Scalar[S interface {
		maurer09.PreImageGroupElement[S]
		algebra.PrimeFieldElement[S]
	}] interface {
		maurer09.PreImageGroupElement[S]
		algebra.PrimeFieldElement[S]
	}

	Group[GE GroupElement[GE, S], S Scalar[S]] interface {
		maurer09.ImageGroup[GE]
		algebra.AbelianGroup[GE, S]
		algebra.FiniteStructure[GE]
	}
	GroupElement[GE interface {
		maurer09.ImageGroupElement[GE]
		algebra.AbelianGroupElement[GE, S]
	}, S Scalar[S]] interface {
		maurer09.ImageGroupElement[GE]
		algebra.AbelianGroupElement[GE, S]
	}
)

type (
	Statement[E GroupElement[E, S], S Scalar[S]]  = maurer09.Statement[S, E]
	Witness[S Scalar[S]]                          = maurer09.Witness[S]
	Commitment[E GroupElement[E, S], S Scalar[S]] = maurer09.Commitment[S, E]
	State[S Scalar[S]]                            = maurer09.State[S]
	Response[S Scalar[S]]                         = maurer09.Response[S]
)

func Phi[E GroupElement[E, S], S Scalar[S]](basePoint E) maurer09.GroupHomomorphism[E, S] {
	return func(s S) E {
		return basePoint.ScalarOp(s)
	}
}

func ChallengeActionOnPreImage[S Scalar[S]](c, x S) S {
	return x.Mul(c)
}

func ChallengeActionOnImage[E GroupElement[E, S], S Scalar[S]](c S, x E) E {
	return x.ScalarOp(c)
}

type Protocol[E GroupElement[E, S], S Scalar[S]] struct {
	maurer09.Protocol[S, E, S, ScalarField[S], Group[E, S]]
}

func NewSigmaProtocol[E GroupElement[E, S], S Scalar[S]](basePoint E, prng io.Reader) (sigma.Protocol[*Statement[E, S], *Witness[S], *Commitment[E, S], *State[S], *Response[S]], error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}

	group, ok := basePoint.Structure().(Group[E, S])
	if !ok {
		return nil, errs.NewArgument("base point does not have a group structure")
	}
	if group == nil {
		return nil, errs.NewIsNil("group cannot be nil")
	}
	sf, ok := group.ScalarStructure().(ScalarField[S])
	if !ok {
		return nil, errs.NewArgument("group does not have a scalar field structure")
	}
	hom := Phi(basePoint)
	subProtocol, err := maurer09.NewProtocol(hom, sf, group, sf, ChallengeActionOnPreImage, ChallengeActionOnImage, sf.Random, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create maurer09 protocol")
	}

	return &Protocol[E, S]{
		Protocol: *subProtocol,
	}, nil
}

func (p *Protocol[E, S]) Name() sigma.Name {
	return Name
}

func _[S Scalar[S]]() {
	var _ maurer09.ChallengeActionOnPreImage[S, S] = ChallengeActionOnPreImage[S]
}

func _[E GroupElement[E, S], S Scalar[S]]() {
	var _ (sigma.MaurerProtocol[
		*Statement[E, S], *Witness[S], *Commitment[E, S], *State[S], *Response[S],

		ScalarField[S], S,
		Group[E, S], E,
	]) = &Protocol[E, S]{}
}
