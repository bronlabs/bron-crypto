package mat

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type (
	RowVector[S algebra.RingElement[S]]                                               = Matrix[S]
	ModuleValuedRowVector[E algebra.ModuleElement[E, S], S algebra.RingElement[S]]    = ModuleValuedMatrix[E, S]
	ColumnVector[S algebra.RingElement[S]]                                            = Matrix[S]
	ModuleValuedColumnVector[E algebra.ModuleElement[E, S], S algebra.RingElement[S]] = ModuleValuedMatrix[E, S]
)

// NewRowVectorModule creates a MatrixModule for row vectors of the given length over the specified finite ring.
func NewRowVectorModule[S algebra.RingElement[S]](length uint, ring algebra.FiniteRing[S]) (*MatrixModule[S], error) {
	out, err := NewMatrixModule(1, length, ring)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create row vector module")
	}
	return out, nil
}

// NewColumnVectorModule creates a MatrixModule for column vectors of the given length over the specified finite ring.
func NewColumnVectorModule[S algebra.RingElement[S]](length uint, ring algebra.FiniteRing[S]) (*MatrixModule[S], error) {
	out, err := NewMatrixModule(length, 1, ring)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create column vector module")
	}
	return out, nil
}

// NewModuleValuedRowVectorModule creates a ModuleValuedMatrixModule for row vectors of the given length over the specified finite module.
func NewModuleValuedRowVectorModule[E algebra.ModuleElement[E, S], S algebra.RingElement[S]](length uint, module algebra.FiniteModule[E, S]) (*ModuleValuedMatrixModule[E, S], error) {
	out, err := NewModuleValuedMatrixModule(1, length, module)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create module-valued row vector module")
	}
	return out, nil
}

// NewModuleValuedColumnVectorModule creates a ModuleValuedMatrixModule for column vectors of the given length over the specified finite module.
func NewModuleValuedColumnVectorModule[E algebra.ModuleElement[E, S], S algebra.RingElement[S]](length uint, module algebra.FiniteModule[E, S]) (*ModuleValuedMatrixModule[E, S], error) {
	out, err := NewModuleValuedMatrixModule(length, 1, module)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create module-valued column vector module")
	}
	return out, nil
}

// DotProduct computes the dot product of two vectors (row or column).
// Both a and b must be vectors (single row or single column) of the same length.
func DotProduct[S algebra.RingElement[S]](a, b *Matrix[S]) (S, error) {
	ring := a.scalarRing()
	aLen := a.vectorLength()
	bLen := b.vectorLength()
	if aLen < 0 || bLen < 0 {
		return ring.Zero(), ErrDimension.WithMessage("dot product requires vectors: got %dx%d and %dx%d", a.m, a.n, b.m, b.n)
	}
	if aLen != bLen {
		return ring.Zero(), ErrDimension.WithMessage("incompatible vector lengths for dot product: %d and %d", aLen, bLen)
	}
	result := ring.Zero()
	for i := range aLen {
		result = result.Add(a.v[i].Mul(b.v[i]))
	}
	return result, nil
}
