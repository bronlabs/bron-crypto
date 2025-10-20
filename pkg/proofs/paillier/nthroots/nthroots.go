package nthroots

import (
	crand "crypto/rand"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/proofs/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name sigma.Name = "PAILLIER_NTH_ROOTS"

type (
	ScalarGroup  = znstar.PaillierGroup
	Scalar       = znstar.Unit
	Group        = znstar.PaillierGroup
	GroupElement = znstar.Unit
	Challenge    = num.Nat
)

var ChallengeSpace = num.N

type (
	Statement  = maurer09.Statement[Scalar, GroupElement]
	Witness    = maurer09.Witness[Scalar]
	Commitment = maurer09.Commitment[Scalar, GroupElement]
	State      = maurer09.State[Scalar]
	Response   = maurer09.Response[Scalar]
)

func NewStatement(x GroupElement) *Statement {
	return &Statement{
		X: x,
	}
}

func NewWitness(w Scalar) *Witness {
	return &Witness{
		W: w,
	}
}

func Phi(g ScalarGroup) maurer09.GroupHomomorphism[Scalar, GroupElement] {
	return func(s Scalar) GroupElement {
		out, err := g.LiftToNthResidues(s)
		if err != nil {
			panic(err)
		}
		return out
	}
}

func ChallengeActionOnPreImage(c *Challenge, x Scalar) Scalar {
	return x.ScalarExp(c)
}

func ChallengeActionOnImage(c *Challenge, x GroupElement) GroupElement {
	return x.Exp(c)
}

type Protocol struct {
	maurer09.Protocol[Scalar, GroupElement, *Challenge, ScalarGroup, Group]
}

func NewSigmaProtocol(g znstar.PaillierGroup, prng io.Reader) (sigma.Protocol[*Statement, *Witness, *Commitment, *State, *Response], error) {
	if prng == nil {
		prng = crand.Reader
	}
	if g == nil {
		return nil, errs.NewIsNil("g")
	}
	hom := Phi(g)
	subProtocol, err := maurer09.NewProtocol(hom, g, g, ChallengeSpace(), ChallengeActionOnPreImage, ChallengeActionOnImage, g.Random, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create underlying Maurer09 protocol")
	}
	return &Protocol{
		Protocol: *subProtocol,
	}, nil
}

func (p *Protocol) Name() sigma.Name {
	return Name
}
