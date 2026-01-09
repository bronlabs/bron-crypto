package k256

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
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	// CurveName is the curve name.
	CurveName = "secp256k1"
	// Hash2CurveSuite is the hash-to-curve suite string.
	Hash2CurveSuite = "secp256k1_XMD:SHA-256_SSWU_RO_"
	// Hash2CurveScalarSuite is the hash-to-curve scalar suite string.
	Hash2CurveScalarSuite = "secp256k1_XMD:SHA-256_SSWU_RO_SC_"
	compressedPointBytes  = k256Impl.FqBytes + 1
)

var (
	_ curves.Curve[*Point, *BaseFieldElement, *Scalar] = (*Curve)(nil)
	_ curves.Point[*Point, *BaseFieldElement, *Scalar] = (*Point)(nil)
	_ encoding.BinaryMarshaler                         = (*Point)(nil)
	_ encoding.BinaryUnmarshaler                       = (*Point)(nil)

	// compressedPointSize = k256Impl.FqBytes + 1.

	curveInstance *Curve
	curveInitOnce sync.Once
)

// Curve represents the elliptic curve group.
type Curve struct {
	traits.PrimeCurveTrait[*k256Impl.Fp, *k256Impl.Point, *Point, Point]
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

// Cofactor returns the curve cofactor.
func (c *Curve) Cofactor() cardinal.Cardinal {
	return cardinal.New(1)
}

// Order returns the group or field order.
func (c *Curve) Order() cardinal.Cardinal {
	return NewScalarField().Order()
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

	var xBytes [k256Impl.FpBytes]byte
	copy(xBytes[:], input[1:])
	slices.Reverse(xBytes[:])

	var x, y k256Impl.Fp
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

	var x, y k256Impl.Fp
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
func (c *Curve) FromAffine(x, y *BaseFieldElement) (*Point, error) {
	var p Point
	ok := p.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x/y")
	}
	return &p, nil
}

// FromAffineX builds a point from an affine x-coordinate.
func (c *Curve) FromAffineX(x *BaseFieldElement, b bool) (*Point, error) {
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
func (c *Curve) HashWithDst(dst string, bytes []byte) (*Point, error) {
	p := Point{}
	p.V.Hash(dst, bytes)
	return &p, nil
}

// ScalarStructure returns the scalar structure.
func (c *Curve) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

// BaseStructure returns the base field structure.
func (c *Curve) BaseStructure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

// ScalarRing returns the scalar ring.
func (c *Curve) ScalarRing() algebra.ZModLike[*Scalar] {
	return NewScalarField()
}

// ScalarField returns the scalar field.
func (c *Curve) ScalarField() algebra.PrimeField[*Scalar] {
	return NewScalarField()
}

// BaseField returns the base field.
func (c *Curve) BaseField() algebra.FiniteField[*BaseFieldElement] {
	return NewBaseField()
}

// ScalarBaseOp adds a scalar multiple of the generator.
func (c *Curve) ScalarBaseOp(sc *Scalar) *Point {
	if c == nil {
		return nil
	}
	if sc == nil {
		panic("scalar is nil")
	}
	if sc.IsZero() {
		return c.OpIdentity()
	}
	return c.ScalarBaseMul(sc)
}

// ScalarBaseMul multiplies the generator by a scalar.
func (c *Curve) ScalarBaseMul(sc *Scalar) *Point {
	if c == nil {
		return nil
	}
	if sc == nil {
		panic("scalar is nil")
	}
	return c.Generator().ScalarMul(sc)
}

// FromBytes decodes an element from bytes.
func (c *Curve) FromBytes(data []byte) (*Point, error) {
	return c.FromCompressed(data)
}

// ToElliptic returns the standard library elliptic.Curve adapter.
func (c *Curve) ToElliptic() elliptic.Curve {
	return ellipticK256Instance
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
	pts := make([]*k256Impl.Point, len(points))
	for i := range points {
		pts[i] = &points[i].V
		scs[i] = scalars[i].V.Bytes()
	}
	aimpl.MultiScalarMulLowLevel(&result.V, pts, scs)
	return &result, nil
}

// Point represents a curve point.
type Point struct {
	traits.PrimePointTrait[*k256Impl.Fp, *k256Impl.Point, k256Impl.Point, *Point, Point]
}

// HashCode returns a hash code for the receiver.
func (p *Point) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

// Structure returns the algebraic structure for the receiver.
func (p Point) Structure() algebra.Structure[*Point] {
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

// Bytes returns the canonical byte encoding.
func (p *Point) Bytes() []byte {
	return p.ToCompressed()
}

// ToCompressed encodes the point in compressed form.
func (p *Point) ToCompressed() []byte {
	var compressedBytes [compressedPointBytes]byte
	compressedBytes[0] = byte(2)
	if p.IsOpIdentity() {
		return compressedBytes[:]
	}

	var px, py k256Impl.Fp
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

// ToUncompressed encodes the point in uncompressed form.
func (p *Point) ToUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	if p.IsOpIdentity() {
		return out[:]
	}

	var px, py k256Impl.Fp
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
func (p *Point) IsTorsionFree() bool {
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
