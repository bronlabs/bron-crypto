package cggmp21

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

type Parameters struct {
	kappa   int
	l       int
	epsilon int
	lPrime  int
	logN    int
}

func NewParameters[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve sigecdsa.Curve[P, B, S], paillierKeyLen int) (*Parameters, error) {
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

	kappa := nextMultipleOf8(curve.ScalarField().BitLen())
	l := kappa
	epsilon := l + kappa
	lPrime := l + epsilon + 2*l
	logN := paillierKeyLen
	if logN < lPrime+epsilon {
		return nil, ErrFailed.WithMessage("key length too short")
	}

	params := &Parameters{
		kappa,
		l,
		epsilon,
		lPrime,
		logN,
	}
	return params, nil
}

func (p *Parameters) Kappa() int {
	return p.kappa
}

func (p *Parameters) L() int {
	return p.l
}

func (p *Parameters) Epsilon() int {
	return p.epsilon
}

func (p *Parameters) LPrime() int {
	return p.lPrime
}

func (p *Parameters) LogN() int {
	return p.logN
}

func nextMultipleOf8(x int) int {
	return (x + 7) &^ 7
}
