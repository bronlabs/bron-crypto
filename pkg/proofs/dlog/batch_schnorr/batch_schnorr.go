package batch_schnorr

import (
	crand "crypto/rand"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name sigma.Name = "BATCH_SCHNORR" + dlog.Type

type (
	PreImageFactorGroup[BS schnorr.Scalar[BS]]        = schnorr.ScalarField[BS]
	PreImageFactorGroupElement[BS schnorr.Scalar[BS]] = schnorr.Scalar[BS]

	ImageFactorGroup[GE schnorr.GroupElement[GE, BS], BS schnorr.Scalar[BS]]        = schnorr.Group[GE, BS]
	ImageFactorGroupElement[GE schnorr.GroupElement[GE, BS], BS schnorr.Scalar[BS]] = schnorr.GroupElement[GE, BS]

	PreImageGroup[S PreImageFactorGroupElement[S]]        = polynomials.PolynomialRing[S]
	PreImageGroupElement[S PreImageFactorGroupElement[S]] = polynomials.Polynomial[S]

	ImageGroup[GE ImageFactorGroupElement[GE, BS], BS PreImageFactorGroupElement[BS]]        = polynomials.PolynomialModule[GE, BS]
	ImageGroupElement[GE ImageFactorGroupElement[GE, BS], BS PreImageFactorGroupElement[BS]] = polynomials.ModuleValuedPolynomial[GE, BS]
)

type (
	Statement[BE ImageFactorGroupElement[BE, BS], BS PreImageFactorGroupElement[BS]]  = maurer09.Statement[PreImageGroupElement[BS], ImageGroupElement[BE, BS]]
	Witness[BE PreImageFactorGroupElement[BE]]                                        = maurer09.Witness[PreImageGroupElement[BE]]
	Commitment[BE ImageFactorGroupElement[BE, BS], BS PreImageFactorGroupElement[BS]] = maurer09.Commitment[PreImageGroupElement[BS], ImageGroupElement[BE, BS]]
	State[BE PreImageFactorGroupElement[BE]]                                          = maurer09.State[PreImageGroupElement[BE]]
	Response[BE PreImageFactorGroupElement[BE]]                                       = maurer09.Response[PreImageGroupElement[BE]]
)

func Phi[BE ImageFactorGroupElement[BE, BS], BS PreImageFactorGroupElement[BS]](basePoint BE) maurer09.GroupHomomorphism[PreImageGroupElement[BS], ImageGroupElement[BE, BS]] {
	return func(s PreImageGroupElement[BS]) ImageGroupElement[BE, BS] {
		out, err := polynomials.LiftToExponent(s, basePoint)
		if err != nil {
			panic(errs.WrapFailed(err, "cannot lift scalar to exponent"))
		}
		return out
	}
}

func ChallengeActionOnPreImage[BS PreImageFactorGroupElement[BS]](c BS, x PreImageGroupElement[BS]) PreImageGroupElement[BS] {
	return x.ScalarMul(c)
}

func ChallengeActionOnImage[BE ImageFactorGroupElement[BE, BS], BS PreImageFactorGroupElement[BS]](c BS, x ImageGroupElement[BE, BS]) ImageGroupElement[BE, BS] {
	return x.ScalarOp(c)
}

func RandomPreImageGroupElement[BS PreImageFactorGroupElement[BS]](preImageGroup PreImageGroup[BS], batchSize uint, prng io.Reader) (PreImageGroupElement[BS], error) {
	if preImageGroup == nil {
		return nil, errs.NewIsNil("pre-image group cannot be nil")
	}
	var err error
	out := preImageGroup.Zero()
	for sliceutils.Any(out.Coefficients(), func(c BS) bool { return c.IsZero() }) {
		out, err = preImageGroup.RandomPolynomial(int(batchSize-1), prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "cannot create random pre-image group element")
		}
	}
	return out, nil
}

type Protocol[BE ImageFactorGroupElement[BE, BS], BS PreImageFactorGroupElement[BS]] struct {
	maurer09.Protocol[PreImageGroupElement[BS], ImageGroupElement[BE, BS], BS]
	batchSize uint
}

func NewSigmaProtocol[E ImageFactorGroupElement[E, S], S PreImageFactorGroupElement[S]](basePoint E, batchSize uint, prng io.Reader) (sigma.Protocol[*Statement[E, S], *Witness[S], *Commitment[E, S], *State[S], *Response[S]], error) {
	if prng == nil {
		prng = crand.Reader
	}
	imageFactorGroup, ok := basePoint.Structure().(ImageFactorGroup[E, S])
	if !ok {
		return nil, errs.NewArgument("base point does not have the factor group's structure")
	}
	imageGroup, err := polynomials.NewPolynomialModule(imageFactorGroup)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create image group")
	}
	preImageFactorGroup, ok := imageFactorGroup.ScalarStructure().(PreImageFactorGroup[S])
	if !ok {
		return nil, errs.NewArgument("image group's scalar structure is not compatible with pre-image factor group")
	}
	preImagePolyRing, err := polynomials.NewPolynomialRing(preImageFactorGroup)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create pre-image group")
	}
	preImageGroup, ok := preImagePolyRing.(PreImageGroup[S])
	if !ok {
		return nil, errs.NewArgument("pre-image polynomial ring does not implement PreImageGroup")
	}
	hom := Phi(basePoint)
	sampler := func(prng io.Reader) (PreImageGroupElement[S], error) {
		return RandomPreImageGroupElement(preImageGroup, batchSize, prng)
	}
	subProtocol, err := maurer09.NewProtocol[PreImageGroupElement[S], ImageGroupElement[E, S], S](
		hom, preImageGroup, imageGroup, preImageFactorGroup, ChallengeActionOnPreImage, ChallengeActionOnImage, sampler, prng,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create maurer09 protocol")
	}

	return &Protocol[E, S]{
		Protocol:  *subProtocol,
		batchSize: batchSize,
	}, nil
}

func (p *Protocol[E, S]) Name() sigma.Name {
	return Name
}

func _[BS PreImageFactorGroupElement[BS]]() {
	var _ maurer09.ChallengeActionOnPreImage[BS, PreImageGroupElement[BS]] = ChallengeActionOnPreImage[BS]
}
