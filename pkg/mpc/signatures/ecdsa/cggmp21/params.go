package cggmp21

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// Parameters holds the CGGMP21 range and curve parameters derived from the curve and Paillier key size.
type Parameters[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve       sigecdsa.Curve[P, B, S]
	scalarField algebra.PrimeField[S]
	kappa       int
	l           int
	epsilon     int
	lPrime      int
	logN        int
}

// NewParameters constructs CGGMP21 parameters for a curve and Paillier modulus bit length.
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

// CurveGroup returns the ECDSA curve group.
func (p *Parameters[P, B, S]) CurveGroup() sigecdsa.Curve[P, B, S] {
	return p.curve
}

// ScalarField returns the ECDSA scalar field.
func (p *Parameters[P, B, S]) ScalarField() algebra.PrimeField[S] {
	return p.scalarField
}

// Kappa returns the byte-aligned curve security parameter.
func (p *Parameters[P, B, S]) Kappa() int {
	return p.kappa
}

// L returns the CGGMP21 ell range parameter.
func (p *Parameters[P, B, S]) L() int {
	return p.l
}

// Epsilon returns the CGGMP21 statistical slack parameter.
func (p *Parameters[P, B, S]) Epsilon() int {
	return p.epsilon
}

// LPrime returns the CGGMP21 ell-prime range parameter.
func (p *Parameters[P, B, S]) LPrime() int {
	return p.lPrime
}

// LogN returns the Paillier modulus bit length.
func (p *Parameters[P, B, S]) LogN() int {
	return p.logN
}

func nextMultipleOf8(x int) int {
	return (x + 7) &^ 7
}
