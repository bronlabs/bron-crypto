package cggmp21

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

type Parameters[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve       sigecdsa.Curve[P, B, S]
	scalarField algebra.PrimeField[S]
	kappa       int
	l           int
	epsilon     int
	lPrime      int
	logN        int
}

func NewParameters[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve sigecdsa.Curve[P, B, S], paillierKeyLen int) (*Parameters[P, B, S], error) {
	if utils.IsNil(curve) {
		return nil, ErrNil.WithMessage("curve")
	}
	if paillierKeyLen < 8 || (paillierKeyLen%8) != 0 {
		return nil, ErrFailed.WithMessage("key length too short or unaligned")
	}
	if !testing.Testing() {
		if paillierKeyLen < base.IFCKeyLength {
			return nil, ErrFailed.WithMessage("key length too short")
		}
	}

	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())
	kappa := nextMultipleOf8(scalarField.BitLen())
	l := kappa
	epsilon := l + kappa
	lPrime := l + epsilon + 2*l
	logN := paillierKeyLen
	if logN < lPrime+epsilon {
		return nil, ErrFailed.WithMessage("key length too short")
	}

	params := &Parameters[P, B, S]{
		curve,
		scalarField,
		kappa,
		l,
		epsilon,
		lPrime,
		logN,
	}
	return params, nil
}

func (p *Parameters[P, B, S]) CurveGroup() sigecdsa.Curve[P, B, S] {
	return p.curve
}

func (p *Parameters[P, B, S]) ScalarField() algebra.PrimeField[S] {
	return p.scalarField
}

func (p *Parameters[P, B, S]) Kappa() int {
	return p.kappa
}

func (p *Parameters[P, B, S]) L() int {
	return p.l
}

func (p *Parameters[P, B, S]) Epsilon() int {
	return p.epsilon
}

func (p *Parameters[P, B, S]) LPrime() int {
	return p.lPrime
}

func (p *Parameters[P, B, S]) LogN() int {
	return p.logN
}

func nextMultipleOf8(x int) int {
	return (x + 7) &^ 7
}
