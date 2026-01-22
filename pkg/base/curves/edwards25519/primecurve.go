package edwards25519

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/errs-go/errs"
)

const (
	// PrimeCurveName is the prime subgroup curve name.
	PrimeCurveName = CurveName + "(PrimeSubGroup)"
)

var (
	_ curves.Curve[*PrimeSubGroupPoint, *BaseFieldElement, *Scalar] = (*PrimeSubGroup)(nil)
	_ curves.Point[*PrimeSubGroupPoint, *BaseFieldElement, *Scalar] = (*PrimeSubGroupPoint)(nil)

	primeSubGroupInstance *PrimeSubGroup
	primeSubGroupInitOnce sync.Once
)

// NewPrimeSubGroup returns the prime subgroup instance.
func NewPrimeSubGroup() *PrimeSubGroup {
	primeSubGroupInitOnce.Do(func() {
		//nolint:exhaustruct // no need for a trait
		primeSubGroupInstance = &PrimeSubGroup{}
	})

	return primeSubGroupInstance
}

// PrimeSubGroup represents the prime-order subgroup.
type PrimeSubGroup struct {
	traits.PrimeCurveTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, *PrimeSubGroupPoint, PrimeSubGroupPoint]
}

// Name returns the name of the structure.
func (*PrimeSubGroup) Name() string {
	return PrimeCurveName
}

// ElementSize returns the element size in bytes.
func (*PrimeSubGroup) ElementSize() int {
	return compressedPointBytes
}

// Cofactor returns the curve cofactor.
func (*PrimeSubGroup) Cofactor() cardinal.Cardinal {
	return cardinal.New(8)
}

// Order returns the group or field order.
func (*PrimeSubGroup) Order() cardinal.Cardinal {
	return NewScalarField().Order()
}

// FromCompressed decodes a compressed point.
func (*PrimeSubGroup) FromCompressed(inBytes []byte) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().FromCompressed(inBytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot deserialize point")
	}
	return p.AsPrimeSubGroupPoint()
}

// FromBytes decodes an element from bytes.
func (*PrimeSubGroup) FromBytes(inBytes []byte) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().FromBytes(inBytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot deserialize point")
	}
	return p.AsPrimeSubGroupPoint()
}

// FromUncompressed decodes an uncompressed point.
func (*PrimeSubGroup) FromUncompressed(inBytes []byte) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().FromUncompressed(inBytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot deserialize point")
	}
	return p.AsPrimeSubGroupPoint()
}

// FromAffine builds a point from affine coordinates.
func (*PrimeSubGroup) FromAffine(x, y *BaseFieldElement) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().FromAffine(x, y)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot set coordinates")
	}
	return p.AsPrimeSubGroupPoint()
}

// Hash maps input bytes to an element or point.
func (*PrimeSubGroup) Hash(bytes []byte) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().Hash(bytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot hash to curve")
	}
	return p.AsPrimeSubGroupPoint()
}

// HashWithDst maps input bytes to a point with a custom DST.
func (*PrimeSubGroup) HashWithDst(dst string, bytes []byte) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().HashWithDst(dst, bytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot hash to curve")
	}
	return p.AsPrimeSubGroupPoint()
}

// ScalarStructure returns the scalar structure.
func (*PrimeSubGroup) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

// ScalarRing returns the scalar ring.
func (*PrimeSubGroup) ScalarRing() algebra.ZModLike[*Scalar] {
	return NewScalarField()
}

// ScalarField returns the scalar field.
func (*PrimeSubGroup) ScalarField() algebra.PrimeField[*Scalar] {
	return NewScalarField()
}

// BaseField returns the base field.
func (*PrimeSubGroup) BaseField() algebra.FiniteField[*BaseFieldElement] {
	return NewBaseField()
}

// BaseStructure returns the base field structure.
func (*PrimeSubGroup) BaseStructure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

// ScalarBaseOp adds a scalar multiple of the generator.
func (c *PrimeSubGroup) ScalarBaseOp(sc *Scalar) *PrimeSubGroupPoint {
	if sc.IsZero() {
		return c.OpIdentity()
	}
	return c.ScalarBaseMul(sc)
}

// ScalarBaseMul multiplies the generator by a scalar.
func (c *PrimeSubGroup) ScalarBaseMul(sc *Scalar) *PrimeSubGroupPoint {
	return c.Generator().ScalarMul(sc)
}

// MultiScalarOp computes a multiscalar operation.
func (c *PrimeSubGroup) MultiScalarOp(scalars []*Scalar, points []*PrimeSubGroupPoint) (*PrimeSubGroupPoint, error) {
	return c.MultiScalarMul(scalars, points)
}

// MultiScalarMul computes a multiscalar multiplication.
func (*PrimeSubGroup) MultiScalarMul(scalars []*Scalar, points []*PrimeSubGroupPoint) (*PrimeSubGroupPoint, error) {
	if len(scalars) != len(points) {
		return nil, curves.ErrInvalidLength.WithMessage("mismatched lengths of scalars and points")
	}
	var result PrimeSubGroupPoint
	scs := make([][]byte, len(scalars))
	pts := make([]*edwards25519Impl.Point, len(points))
	for i := range points {
		pts[i] = &points[i].V
		scs[i] = scalars[i].V.Bytes()
	}
	aimpl.MultiScalarMulLowLevel(&result.V, pts, scs)
	return &result, nil
}

// PrimeSubGroupPoint represents a point in the prime-order subgroup.
type PrimeSubGroupPoint struct {
	traits.PrimePointTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, edwards25519Impl.Point, *PrimeSubGroupPoint, PrimeSubGroupPoint]
}

// HashCode returns a hash code for the receiver.
func (p *PrimeSubGroupPoint) HashCode() base.HashCode {
	return p.AsPoint().HashCode()
}

// Structure returns the algebraic structure for the receiver.
func (*PrimeSubGroupPoint) Structure() algebra.Structure[*PrimeSubGroupPoint] {
	return NewPrimeSubGroup()
}

// ToCompressed encodes the point in compressed form.
func (p *PrimeSubGroupPoint) ToCompressed() []byte {
	return p.AsPoint().ToCompressed()
}

// ToUncompressed encodes the point in uncompressed form.
func (p *PrimeSubGroupPoint) ToUncompressed() []byte {
	return p.AsPoint().ToUncompressed()
}

// AffineX returns the affine x-coordinate.
func (p *PrimeSubGroupPoint) AffineX() (*BaseFieldElement, error) {
	return p.AsPoint().AffineX()
}

// AffineY returns the affine y-coordinate.
func (p *PrimeSubGroupPoint) AffineY() (*BaseFieldElement, error) {
	return p.AsPoint().AffineY()
}

// ScalarOp adds a scalar multiple of q to the receiver.
func (p *PrimeSubGroupPoint) ScalarOp(sc *Scalar) *PrimeSubGroupPoint {
	return p.ScalarMul(sc)
}

// ScalarMul multiplies the point by a scalar.
func (p *PrimeSubGroupPoint) ScalarMul(actor *Scalar) *PrimeSubGroupPoint {
	var result PrimeSubGroupPoint
	aimpl.ScalarMulLowLevel(&result.V, &p.V, actor.V.Bytes())
	return &result
}

// IsTorsionFree reports whether the point is torsion-free.
func (*PrimeSubGroupPoint) IsTorsionFree() bool {
	return true
}

// Bytes returns the canonical byte encoding.
func (p *PrimeSubGroupPoint) Bytes() []byte {
	return p.AsPoint().Bytes()
}

// String returns the string form of the receiver.
func (p *PrimeSubGroupPoint) String() string {
	return p.AsPoint().String()
}

// AsPoint converts the prime subgroup point to a curve point.
func (p *PrimeSubGroupPoint) AsPoint() *Point {
	var pp Point
	pp.V.Set(&p.V)
	return &pp
}
