package edwards25519

import (
	"encoding"
	"fmt"
	"hash/fnv"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	// CurveName is the curve name.
	CurveName = "edwards25519"
	// Hash2CurveSuite is the hash-to-curve suite string.
	Hash2CurveSuite = "edwards25519_XMD:SHA-512_ELL2_NU_"
	// Hash2CurveScalarSuite is the hash-to-curve scalar suite string.
	Hash2CurveScalarSuite = "edwards25519_XMD:SHA-512_ELL2_NU_SC_"
	compressedPointBytes  = edwards25519Impl.FpBytes
)

var (
	_ curves.EllipticCurve[*Point, *BaseFieldElement, *Scalar] = (*Curve)(nil)
	_ curves.ECPoint[*Point, *BaseFieldElement, *Scalar]       = (*Point)(nil)
	_ encoding.BinaryMarshaler                                 = (*Point)(nil)
	_ encoding.BinaryUnmarshaler                               = (*Point)(nil)

	curveInstance *Curve
	curveInitOnce sync.Once
)

// Curve represents the elliptic curve group.
type Curve struct {
	traits.CurveTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, *Point, Point]
}

// NewCurve returns the curve instance.
func NewCurve() *Curve {
	curveInitOnce.Do(func() {
		//nolint:exhaustruct // no need for a trait
		curveInstance = &Curve{}
	})

	return curveInstance
}

// Name returns the name of the structure.
func (c *Curve) Name() string {
	return CurveName
}

// ElementSize returns the element size in bytes.
func (c *Curve) ElementSize() int {
	return compressedPointBytes
}

// WideElementSize returns the wide element size in bytes.
func (c *Curve) WideElementSize() int {
	return int(^uint(0) >> 1)
}

// FromWideBytes decodes an element from wide bytes.
func (c *Curve) FromWideBytes(input []byte) (*Point, error) {
	return c.Hash(input)
}

// Cofactor returns the curve cofactor.
func (c *Curve) Cofactor() cardinal.Cardinal {
	return cardinal.New(8)
}

// Order returns the group or field order.
func (c *Curve) Order() cardinal.Cardinal {
	return NewScalarField().Order()
}

// FromCompressed decodes a compressed point.
func (c *Curve) FromCompressed(inBytes []byte) (*Point, error) {
	if len(inBytes) != int(compressedPointBytes) {
		return nil, curves.ErrInvalidLength.WithMessage("input must be 32 bytes long")
	}

	var yBytes [32]byte
	copy(yBytes[:], inBytes)
	var y BaseFieldElement
	yBytes[31] &= 0x7f
	ok := y.V.SetBytes(yBytes[:])
	if ok != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid point")
	}

	var x BaseFieldElement
	result := new(Point)
	ok = result.V.SetFromAffineY(&y.V)
	_ = result.V.ToAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid point")
	}

	isOdd := ct.Bool(inBytes[31] >> 7)
	if fieldsImpl.IsOdd(&x.V) != isOdd {
		result = result.Neg()
	}

	return result, nil
}

// FromBytes decodes an element from bytes.
func (c *Curve) FromBytes(input []byte) (*Point, error) {
	return c.FromCompressed(input)
}

// FromUncompressed decodes an uncompressed point.
func (c *Curve) FromUncompressed(inBytes []byte) (*Point, error) {
	if len(inBytes) != 2*32 {
		return nil, curves.ErrInvalidLength.WithMessage("invalid byte sequence")
	}
	yBytes := inBytes[:32]
	xBytes := inBytes[32:]

	var x, y BaseFieldElement
	ok := x.V.SetBytes(xBytes)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x")
	}
	ok = y.V.SetBytes(yBytes)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("y")
	}

	result := new(Point)
	ok = result.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x/y")
	}

	return result, nil
}

// FromAffine builds a point from affine coordinates.
func (c *Curve) FromAffine(x, y *BaseFieldElement) (*Point, error) {
	var p Point
	ok := p.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x/y")
	}
	return &p, nil
}

// Hash maps input bytes to an element or point.
func (c *Curve) Hash(bytes []byte) (*Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuite, bytes)
}

// HashWithDst maps input bytes to a point with a custom DST.
func (c *Curve) HashWithDst(dst string, bytes []byte) (*Point, error) {
	var p Point
	p.V.Hash(dst, bytes)
	return &p, nil
}

// ScalarRing returns the scalar ring.
func (c *Curve) ScalarRing() algebra.ZModLike[*Scalar] {
	return NewScalarField()
}

// ScalarStructure returns the scalar structure.
func (c *Curve) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

// BaseStructure returns the base field structure.
func (c *Curve) BaseStructure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

// BaseField returns the base field.
func (c *Curve) BaseField() algebra.FiniteField[*BaseFieldElement] {
	return NewBaseField()
}

// MultiScalarOp computes a multiscalar operation.
func (c *Curve) MultiScalarOp(scalars []*Scalar, points []*Point) (*Point, error) {
	return c.MultiScalarMul(scalars, points)
}

// MultiScalarMul computes a multiscalar multiplication.
func (c *Curve) MultiScalarMul(scalars []*Scalar, points []*Point) (*Point, error) {
	if len(scalars) != len(points) {
		return nil, curves.ErrInvalidLength.WithMessage("mismatched lengths of scalars and points")
	}
	var result Point
	scs := make([][]byte, len(scalars))
	pts := make([]*edwards25519Impl.Point, len(points))
	for i := range points {
		pts[i] = &points[i].V
		scs[i] = scalars[i].V.Bytes()
	}
	aimpl.MultiScalarMulLowLevel(&result.V, pts, scs)
	return &result, nil
}

// Point represents a curve point.
type Point struct {
	traits.PointTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, edwards25519Impl.Point, *Point, Point]
}

// HashCode returns a hash code for the receiver.
func (p *Point) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

// Structure returns the algebraic structure for the receiver.
func (p *Point) Structure() algebra.Structure[*Point] {
	return NewCurve()
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (p *Point) MarshalBinary() (data []byte, err error) {
	return p.ToCompressed(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (p *Point) UnmarshalBinary(data []byte) error {
	pp, err := NewCurve().FromCompressed(data)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot deserialize point")
	}

	p.V.Set(&pp.V)
	return nil
}

// ToCompressed encodes the point in compressed form.
func (p *Point) ToCompressed() []byte {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)
	yBytes := y.V.Bytes()
	yBytes[31] |= byte(fieldsImpl.IsOdd(&x.V) << 7)
	return yBytes
}

// ToUncompressed encodes the point in uncompressed form.
func (p *Point) ToUncompressed() []byte {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)

	return slices.Concat(y.V.Bytes(), x.V.Bytes())
}

// AffineX returns the affine x-coordinate.
func (p *Point) AffineX() (*BaseFieldElement, error) {
	if p.IsZero() {
		return nil, curves.ErrFailed.WithMessage("point is identity")
	}
	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x, nil
}

// AffineY returns the affine y-coordinate.
func (p *Point) AffineY() (*BaseFieldElement, error) {
	if p.IsZero() {
		return nil, curves.ErrFailed.WithMessage("point is identity")
	}

	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y, nil
}

// ScalarOp adds a scalar multiple of q to the receiver.
func (p *Point) ScalarOp(sc *Scalar) *Point {
	return p.ScalarMul(sc)
}

// ScalarMul multiplies the point by a scalar.
func (p *Point) ScalarMul(actor *Scalar) *Point {
	var result Point
	aimpl.ScalarMulLowLevel(&result.V, &p.V, actor.V.Bytes())
	return &result
}

// IsTorsionFree reports whether the point is torsion-free.
func (p *Point) IsTorsionFree() bool {
	primeOrderBytes := NewScalarField().Order().Bytes()
	slices.Reverse(primeOrderBytes)
	var e edwards25519Impl.Point
	aimpl.ScalarMulLowLevel(&e, &p.V, primeOrderBytes)
	return e.IsZero() == 1
}

// Bytes returns the canonical byte encoding.
func (p *Point) Bytes() []byte {
	return p.ToCompressed()
}

// String returns the string form of the receiver.
func (p *Point) String() string {
	if p.IsZero() {
		return "(0, 1, 0, 1)"
	} else {
		return fmt.Sprintf("(%s, %s, %s, %s)", p.V.X.String(), p.V.Y.String(), p.V.T.String(), p.V.Z.String())
	}
}

// AsPrimeSubGroupPoint converts to a prime subgroup point if torsion-free.
func (p *Point) AsPrimeSubGroupPoint() (*PrimeSubGroupPoint, error) {
	if !p.IsTorsionFree() {
		return nil, curves.ErrFailed.WithMessage("point is not in the prime subgroup")
	}

	var pp PrimeSubGroupPoint
	pp.V.Set(&p.V)
	return &pp, nil
}
