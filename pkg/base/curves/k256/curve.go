package k256

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"slices"
	"sync"
)

const (
	CurveName             = "secp256k1"
	Hash2CurveSuite       = "secp256k1_XMD:SHA-256_SSWU_RO_"
	Hash2CurveScalarSuite = "secp256k1_XMD:SHA-256_SSWU_RO_SC_"
)

var (
	_ curves.Curve[*Point, *BaseFieldElement, *Scalar] = (*Curve)(nil)
	_ curves.Point[*Point, *BaseFieldElement, *Scalar] = (*Point)(nil)

	curveInstance *Curve
	curveInitOnce sync.Once
)

type Curve struct {
	traits.Curve[*k256Impl.Fp, *k256Impl.Point, *Point, Point]
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

func (c *Curve) Order() algebra.Cardinal {
	return scalarFieldOrder.Nat()
}

func (c *Curve) Operator() algebra.BinaryOperator[*Point] {
	return algebra.Add[*Point]
}

func (c *Curve) FromAffineCompressed(input []byte) (*Point, error) {
	if len(input) != 33 {
		return nil, errs.NewLength("invalid byte sequence")
	}

	sign := input[0]
	if sign != 2 && sign != 3 {
		return nil, errs.NewFailed("invalid sign byte")
	}
	sign &= 0x1

	var xBytes [k256Impl.FpBytes]byte
	copy(xBytes[:], input[1:])
	slices.Reverse(xBytes[:])

	var x, y k256Impl.Fp
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

func (c *Curve) FromAffineUncompressed(input []byte) (*Point, error) {
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

	var x, y k256Impl.Fp
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

func (c *Curve) NewPoint(affineX, affineY *BaseFieldElement) (*Point, error) {
	//TODO implement me
	panic("implement me")
}

func (c *Curve) Hash(bytes []byte) (*Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuite, bytes)
}

func (c *Curve) HashWithDst(dst string, bytes []byte) (*Point, error) {
	var p Point
	p.V.Hash(dst, bytes)
	return &p, nil
}

// TODO(aalireza): doesn't make sense of curve/point
func (c *Curve) ElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (c *Curve) WideElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (c *Curve) BasePoints() ds.ImmutableMap[string, *Point] {
	panic("implement me")
}

func (c *Curve) ScalarField() algebra.PrimeField[*Scalar] {
	return NewScalarField()
}

func (c *Curve) BaseField() algebra.FiniteField[*BaseFieldElement] {
	return NewBaseField()
}

type Point struct {
	traits.Point[*k256Impl.Fp, *k256Impl.Point, k256Impl.Point, *Point, Point]
}

func (p *Point) P() *k256Impl.Point {
	return &p.V
}

func (p *Point) HashCode() uint64 {
	//TODO implement me
	panic("implement me")
}

func (p *Point) Structure() algebra.Structure[*Point] {
	return NewCurve()
}

func (p *Point) MarshalBinary() (data []byte, err error) {
	//TODO implement me
	panic("implement me")
}

func (p *Point) UnmarshalBinary(data []byte) error {
	//TODO implement me
	panic("implement me")
}

// TODO(aalireza): not sure if this should always return affine coordinates or implementation defined coordinates
func (p *Point) Coordinates() []*BaseFieldElement {
	var x, y BaseFieldElement
	p.V.ToAffine(&x.V, &y.V)

	return []*BaseFieldElement{&x, &y}
}

func (p *Point) ToAffineCompressed() []byte {
	var compressedBytes [33]byte
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

func (p *Point) ToAffineUncompressed() []byte {
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

func (p *Point) AffineX() *BaseFieldElement {
	if p.IsZero() {
		return NewBaseField().One()
	}

	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x
}

func (p *Point) AffineY() *BaseFieldElement {
	if p.IsZero() {
		return NewBaseField().Zero()
	}

	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y
}

func (p *Point) ScalarMul(actor *Scalar) *Point {
	var result Point
	pointsImpl.ScalarMul[*k256Impl.Fp](&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *Point) IsTorsionFree() bool {
	return true
}

func (p *Point) IsBasePoint(id string) bool {
	//TODO implement me
	panic("implement me")
}

// TODO(aalireza): no use of it
func (p *Point) CanBeGenerator() bool {
	//TODO implement me
	panic("implement me")
}
