package rvole

import (
	"math"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
)

const (
	transcriptLabel = "BRON_CRYPTO-RVOLE-"
	gadgetLabel     = "BRON_CRYPTO-RVOLE-GADGET-"
	aTildeLabel     = "BRON_CRYPTO-RVOLE-A_TILDE-"
	thetaLabel      = "BRON_CRYPTO-RVOLE-THETA-"
	muVectorLabel   = "BRON_CRYPTO-RVOLE-MU_VECTOR-"
	muLabel         = "BRON_CRYPTO-RVOLE-MU-"

	// rho is the number of masking columns â appended to Alice's input. One
	// suffices whenever log q ≥ κ + 2·log ξ (Asharov, Claim B.8), which
	// NewSuite checks.
	rho = 1
	// otBlock is the granularity of the random OT extension: ξ must be a
	// multiple of it, and the extension adds otBlock check rows of its own.
	otBlock = 128
)

// Suite bundles the protocol parameters: the vector length ℓ, the curve whose
// scalar field is the OLE ring and the number of OTs ξ derived from it.
type Suite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	l     int
	xi    int
	curve curves.Curve[P, B, S]
	field algebra.PrimeField[S]
}

// NewSuite fixes ℓ > 0 and the curve, and sets ξ to the Variant III bound for
// the library's statistical security parameter, rounded up to a multiple of
// otBlock. It rejects fields too small for ρ = 1.
func NewSuite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](l int, curve curves.Curve[P, B, S]) (*Suite[P, B, S], error) {
	if curve == nil {
		return nil, ErrInvalidArgument.WithMessage("curve must not be nil")
	}
	if l <= 0 {
		return nil, ErrInvalidArgument.WithMessage("l must be positive, got %d", l)
	}
	field := curve.ScalarField()
	logQ := field.Order().BitLen()
	xi := otCount(logQ)
	if logQ < base.ComputationalSecurityBits+2*mathutils.CeilLog2(xi) {
		return nil, ErrInvalidArgument.WithMessage("field of %d bits is too small for rho = 1 with xi = %d", logQ, xi)
	}
	return &Suite[P, B, S]{l: l, xi: xi, curve: curve, field: field}, nil
}

// L returns the vector length ℓ.
func (s *Suite[P, B, S]) L() int {
	return s.l
}

// Xi returns the number of OTs ξ.
func (s *Suite[P, B, S]) Xi() int {
	return s.xi
}

// Curve returns the curve whose scalar field is the OLE ring.
func (s *Suite[P, B, S]) Curve() curves.Curve[P, B, S] {
	return s.curve
}

// Field returns the OLE ring, the curve's scalar field.
func (s *Suite[P, B, S]) Field() algebra.PrimeField[S] {
	return s.field
}

// otCount returns the number of OTs ξ of Variant III (Asharov, Theorem B.17)
// for a field of logQ bits at the library's statistical security s: the least
// m with m ≥ logQ + 7s + 2·log₂(s+1) + 2s·log₂(e·m/s), rounded up to a multiple
// of otBlock. At s = 80 it gives 1792 for 256-bit fields; the paper's Table 1
// value of 1408 corresponds to s = 60.
func otCount(logQ int) int {
	s := float64(base.StatisticalSecurityBits)
	bound := func(m int) float64 {
		return float64(logQ) + 7*s + 2*math.Log2(s+1) + 2*s*math.Log2(math.E*float64(m)/s)
	}
	m := logQ + 7*base.StatisticalSecurityBits
	for float64(m) < bound(m) {
		m++
	}
	return mathutils.CeilDiv(m, otBlock) * otBlock
}
