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
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	CurveName             = "P256"
	Hash2CurveSuite       = "P256_XMD:SHA-256_SSWU_RO_"
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

type Curve struct {
	traits.PrimeCurveTrait[*p256Impl.Fp, *p256Impl.Point, *Point, Point]
	traits.MSMTrait[*Scalar, *Point]
}

func NewCurve() *Curve {
	curveInitOnce.Do(func() {
		curveInstance = &Curve{}
	})

	return curveInstance
}

func (c *Curve) Name() string {
	return CurveName
}

func (c *Curve) ElementSize() int {
	return compressedPointBytes
}

func (c *Curve) WideElementSize() int {
	return int(^uint(0) >> 1)
}

func (c *Curve) FromWideBytes(input []byte) (*Point, error) {
	return c.Hash(input)
}

func (c *Curve) Cofactor() cardinal.Cardinal {
	return cardinal.New(1)
}

func (c *Curve) Order() cardinal.Cardinal {
	return NewScalarField().Order()
}

func (c *Curve) FromCompressed(input []byte) (*Point, error) {
	if len(input) != compressedPointBytes {
		return nil, errs.NewLength("invalid byte sequence")
	}

	sign := input[0]
	if sign != 2 && sign != 3 {
		return nil, errs.NewFailed("invalid sign byte")
	}
	sign &= 0x1

	var xBytes [p256Impl.FpBytes]byte
	copy(xBytes[:], input[1:])
	slices.Reverse(xBytes[:])

	var x, y p256Impl.Fp
	ok := x.SetBytes(xBytes[:])
	if ok != 1 {
		return nil, errs.NewCoordinates("x")
	}
	if x.IsZero() == 1 {
		return c.OpIdentity(), nil
	}

	var result Point
	ok = result.V.SetFromAffineX(&x)
	if ok != 1 {
		return nil, errs.NewCoordinates("x")
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

func (c *Curve) FromBytes(input []byte) (*Point, error) {
	return c.FromCompressed(input)
}

func (c *Curve) FromUncompressed(input []byte) (*Point, error) {
	if len(input) != 65 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	if input[0] != 4 {
		return nil, errs.NewFailed("invalid sign byte")
	}

	var xBytes, yBytes [32]byte
	copy(xBytes[:], input[1:33])
	copy(yBytes[:], input[33:])
	slices.Reverse(xBytes[:])
	slices.Reverse(yBytes[:])

	var x, y p256Impl.Fp
	okx := x.SetBytes(xBytes[:])
	if okx != 1 {
		return nil, errs.NewCoordinates("x")
	}
	oky := y.SetBytes(yBytes[:])
	if oky != 1 {
		return nil, errs.NewCoordinates("y")
	}
	if x.IsZero() == 1 && y.IsZero() == 1 {
		return c.OpIdentity(), nil
	}

	var result Point
	ok := result.V.SetAffine(&x, &y)
	if ok != 1 {
		return nil, errs.NewCoordinates("x/y")
	}

	return &result, nil
}

func (c *Curve) FromAffine(x, y *BaseFieldElement) (*Point, error) {
	var p Point
	ok := p.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, errs.NewCoordinates("x/y")
	}
	return &p, nil
}

func (c *Curve) FromAffineX(x *BaseFieldElement, b bool) (*Point, error) {
	var p Point
	ok := p.V.SetFromAffineX(&x.V)
	if ok != 1 {
		return nil, errs.NewCoordinates("x")
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

func (c *Curve) Hash(bytes []byte) (*Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuite, bytes)
}

func (c *Curve) HashWithDst(dst string, bytes []byte) (*Point, error) {
	var p Point
	p.V.Hash(dst, bytes)
	return &p, nil
}

func (c *Curve) ToElliptic() elliptic.Curve {
	return elliptic.P256()
}

func (c *Curve) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (c *Curve) BaseStructure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

func (c *Curve) ScalarField() algebra.PrimeField[*Scalar] {
	return NewScalarField()
}

func (c *Curve) BaseField() algebra.FiniteField[*BaseFieldElement] {
	return NewBaseField()
}

func (c *Curve) ScalarBaseOp(sc *Scalar) *Point {
	if sc.IsZero() {
		return c.OpIdentity()
	}
	return c.ScalarBaseMul(sc)
}

func (c *Curve) ScalarBaseMul(sc *Scalar) *Point {
	return c.Generator().ScalarMul(sc)
}

type Point struct {
	traits.PrimePointTrait[*p256Impl.Fp, *p256Impl.Point, p256Impl.Point, *Point, Point]
}

func (p *Point) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

func (p *Point) Structure() algebra.Structure[*Point] {
	return NewCurve()
}

func (p *Point) MarshalBinary() (data []byte, err error) {
	return p.ToCompressed(), nil
}

func (p *Point) UnmarshalBinary(data []byte) error {
	pp, err := NewCurve().FromCompressed(data)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}

func (p Point) Coordinates() algebra.Coordinates[*BaseFieldElement] {
	var x, y BaseFieldElement
	p.V.ToAffine(&x.V, &y.V)

	return algebra.NewCoordinates(algebra.AffineCoordinateSystem, &x, &y)
}

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

func (p *Point) Bytes() []byte {
	return p.ToCompressed()
}

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

func (p *Point) AffineX() (*BaseFieldElement, error) {
	if p.IsZero() {
		return nil, errs.NewFailed("point is identity")
	}

	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x, nil
}

func (p *Point) AffineY() (*BaseFieldElement, error) {
	if p.IsZero() {
		return nil, errs.NewFailed("point is identity")
	}

	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y, nil
}

func (p *Point) ScalarOp(sc *Scalar) *Point {
	return p.ScalarMul(sc)
}

func (p *Point) ScalarMul(actor *Scalar) *Point {
	var result Point
	aimpl.ScalarMul(&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *Point) IsTorsionFree() bool {
	return true
}

func (p *Point) String() string {
	if p.IsZero() {
		return "(0, 1, 0)"
	} else {
		return fmt.Sprintf("(%s, %s, %s)", p.V.X.String(), p.V.Y.String(), p.V.Z.String())
	}
}
