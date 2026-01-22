package p256

import (
	"crypto/elliptic"
	"encoding"
	"fmt"
	"hash/fnv"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	// CurveName is the curve name.
	CurveName = "P256"
	// Hash2CurveSuite is the hash-to-curve suite string.
	Hash2CurveSuite = "P256_XMD:SHA-256_SSWU_RO_"
	// Hash2CurveScalarSuite is the hash-to-curve scalar suite string.
	Hash2CurveScalarSuite = "P256_XMD:SHA-256_SSWU_RO_SC_"
	compressedPointBytes  = p256Impl.FpBytes + 1 // 33 bytes for compressed point
)

var (
	_ curves.Curve[*Point, *BaseFieldElement, *Scalar] = (*Curve)(nil)
	_ curves.Point[*Point, *BaseFieldElement, *Scalar] = (*Point)(nil)
	_ encoding.BinaryMarshaler                         = (*Point)(nil)
	_ encoding.BinaryUnmarshaler                       = (*Point)(nil)

	curveInstance *Curve
	curveInitOnce sync.Once
)

// Curve represents the elliptic curve group.
type Curve struct {
	traits.PrimeCurveTrait[*p256Impl.Fp, *p256Impl.Point, *Point, Point]
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
func (*Curve) Name() string {
	return CurveName
}

// ElementSize returns the element size in bytes.
func (*Curve) ElementSize() int {
	return compressedPointBytes
}

// WideElementSize returns the wide element size in bytes.
func (*Curve) WideElementSize() int {
	return int(^uint(0) >> 1)
}

// FromWideBytes decodes an element from wide bytes.
func (c *Curve) FromWideBytes(input []byte) (*Point, error) {
	return c.Hash(input)
}

// Cofactor returns the curve cofactor.
func (*Curve) Cofactor() cardinal.Cardinal {
	return cardinal.New(1)
}

// Order returns the group or field order.
func (*Curve) Order() cardinal.Cardinal {
	return NewScalarField().Order()
}

// FromCompressed decodes a compressed point.
func (c *Curve) FromCompressed(input []byte) (*Point, error) {
	if len(input) != compressedPointBytes {
		return nil, curves.ErrInvalidLength.WithMessage("invalid byte sequence")
	}

	sign := input[0]
	if sign != 2 && sign != 3 {
		return nil, curves.ErrFailed.WithMessage("invalid sign byte")
	}
	sign &= 0x1

	var xBytes [p256Impl.FpBytes]byte
	copy(xBytes[:], input[1:])
	slices.Reverse(xBytes[:])

	var x, y p256Impl.Fp
	ok := x.SetBytes(xBytes[:])
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x")
	}
	if x.IsZero() == 1 {
		return c.OpIdentity(), nil
	}

	var result Point
	ok = result.V.SetFromAffineX(&x)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x")
	}
	ok = result.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}

	ySign := result.V.Y.Bytes()[0] & 0b1
	if sign != ySign {
		result.V.Neg(&result.V)
	}

	return &result, nil
}

// FromBytes decodes an element from bytes.
func (c *Curve) FromBytes(input []byte) (*Point, error) {
	return c.FromCompressed(input)
}

// FromUncompressed decodes an uncompressed point.
func (c *Curve) FromUncompressed(input []byte) (*Point, error) {
	if len(input) != 65 {
		return nil, curves.ErrInvalidLength.WithMessage("invalid byte sequence")
	}
	if input[0] != 4 {
		return nil, curves.ErrFailed.WithMessage("invalid sign byte")
	}

	var xBytes, yBytes [32]byte
	copy(xBytes[:], input[1:33])
	copy(yBytes[:], input[33:])
	slices.Reverse(xBytes[:])
	slices.Reverse(yBytes[:])

	var x, y p256Impl.Fp
	okx := x.SetBytes(xBytes[:])
	if okx != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x")
	}
	oky := y.SetBytes(yBytes[:])
	if oky != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("y")
	}
	if x.IsZero() == 1 && y.IsZero() == 1 {
		return c.OpIdentity(), nil
	}

	var result Point
	ok := result.V.SetAffine(&x, &y)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x/y")
	}

	return &result, nil
}

// FromAffine builds a point from affine coordinates.
func (*Curve) FromAffine(x, y *BaseFieldElement) (*Point, error) {
	var p Point
	ok := p.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x/y")
	}
	return &p, nil
}

// FromAffineX builds a point from an affine x-coordinate.
func (*Curve) FromAffineX(x *BaseFieldElement, b bool) (*Point, error) {
	var p Point
	ok := p.V.SetFromAffineX(&x.V)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x")
	}
	y, err := p.AffineY()
	if err != nil {
		panic(err) // should never happen
	}
	if y.IsOdd() != b {
		return p.Neg(), nil
	} else {
		return &p, nil
	}
}

// Hash maps input bytes to an element or point.
func (c *Curve) Hash(bytes []byte) (*Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuite, bytes)
}

// HashWithDst maps input bytes to a point with a custom DST.
func (*Curve) HashWithDst(dst string, bytes []byte) (*Point, error) {
	var p Point
	p.V.Hash(dst, bytes)
	return &p, nil
}

// ToElliptic returns the standard library elliptic.Curve adapter.
func (*Curve) ToElliptic() elliptic.Curve {
	return elliptic.P256()
}

// ScalarStructure returns the scalar structure.
func (*Curve) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

// BaseStructure returns the base field structure.
func (*Curve) BaseStructure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

// ScalarRing returns the scalar ring.
func (*Curve) ScalarRing() algebra.ZModLike[*Scalar] {
	return NewScalarField()
}

// ScalarField returns the scalar field.
func (*Curve) ScalarField() algebra.PrimeField[*Scalar] {
	return NewScalarField()
}

// BaseField returns the base field.
func (*Curve) BaseField() algebra.FiniteField[*BaseFieldElement] {
	return NewBaseField()
}

// ScalarBaseOp adds a scalar multiple of the generator.
func (c *Curve) ScalarBaseOp(sc *Scalar) *Point {
	if sc.IsZero() {
		return c.OpIdentity()
	}
	return c.ScalarBaseMul(sc)
}

// ScalarBaseMul multiplies the generator by a scalar.
func (c *Curve) ScalarBaseMul(sc *Scalar) *Point {
	return c.Generator().ScalarMul(sc)
}

// MultiScalarOp computes a multiscalar operation.
func (c *Curve) MultiScalarOp(scalars []*Scalar, points []*Point) (*Point, error) {
	return c.MultiScalarMul(scalars, points)
}

// MultiScalarMul computes a multiscalar multiplication.
func (*Curve) MultiScalarMul(scalars []*Scalar, points []*Point) (*Point, error) {
	if len(scalars) != len(points) {
		return nil, curves.ErrInvalidLength.WithMessage("mismatched lengths of scalars and points")
	}
	var result Point
	scs := make([][]byte, len(scalars))
	pts := make([]*p256Impl.Point, len(points))
	for i := range points {
		pts[i] = &points[i].V
		scs[i] = scalars[i].V.Bytes()
	}
	aimpl.MultiScalarMulLowLevel(&result.V, pts, scs)
	return &result, nil
}

// Point represents a curve point.
type Point struct {
	traits.PrimePointTrait[*p256Impl.Fp, *p256Impl.Point, p256Impl.Point, *Point, Point]
}

// HashCode returns a hash code for the receiver.
func (p *Point) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

// Structure returns the algebraic structure for the receiver.
func (*Point) Structure() algebra.Structure[*Point] {
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
		return errs.Wrap(err).WithMessage("cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}

// ToCompressed encodes the point in compressed form.
func (p *Point) ToCompressed() []byte {
	var compressedBytes [compressedPointBytes]byte
	compressedBytes[0] = byte(2)
	if p.IsOpIdentity() {
		return compressedBytes[:]
	}

	var px, py p256Impl.Fp
	ok := p.V.ToAffine(&px, &py)
	if ok != 1 {
		panic("this should never happen")
	}

	compressedBytes[0] |= py.Bytes()[0] & 1
	pxBytes := px.Bytes()
	slices.Reverse(pxBytes)
	copy(compressedBytes[1:], pxBytes)
	return compressedBytes[:]
}

// Bytes returns the canonical byte encoding.
func (p *Point) Bytes() []byte {
	return p.ToCompressed()
}

// ToUncompressed encodes the point in uncompressed form.
func (p *Point) ToUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	if p.IsOpIdentity() {
		return out[:]
	}

	var px, py p256Impl.Fp
	ok := p.V.ToAffine(&px, &py)
	if ok != 1 {
		panic("this should never happen")
	}

	pxBytes := px.Bytes()
	slices.Reverse(pxBytes)
	copy(out[1:33], pxBytes)

	pyBytes := py.Bytes()
	slices.Reverse(pyBytes)
	copy(out[33:], pyBytes)

	return out[:]
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
func (*Point) IsTorsionFree() bool {
	return true
}

// String returns the string form of the receiver.
func (p *Point) String() string {
	if p.IsZero() {
		return "(0, 1, 0)"
	} else {
		return fmt.Sprintf("(%s, %s, %s)", p.V.X.String(), p.V.Y.String(), p.V.Z.String())
	}
}
