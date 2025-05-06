package edwards25519

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"slices"
	"sync"
)

const (
	CurveName             = "edwards25519"
	Hash2CurveSuite       = "edwards25519_XMD:SHA-512_ELL2_NU_"
	Hash2CurveScalarSuite = "edwards25519_XMD:SHA-512_ELL2_NU_SC_"
)

var (
	_ curves.Curve[*Point, *BaseFieldElement, *Scalar] = (*Curve)(nil)
	_ curves.Point[*Point, *BaseFieldElement, *Scalar] = (*Point)(nil)

	curveInstance *Curve
	curveInitOnce sync.Once
)

type Curve struct {
	traits.CurveTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, *Point, Point]
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

func (c *Curve) FromAffineCompressed(inBytes []byte) (*Point, error) {
	if len(inBytes) != 32 {
		return nil, errs.NewLength("input must be 32 bytes long")
	}

	var yBytes [32]byte
	copy(yBytes[:], inBytes)
	var y BaseFieldElement
	yBytes[31] &= 0x7f
	ok := y.V.SetBytes(yBytes[:])
	if ok != 1 {
		return nil, errs.NewFailed("invalid point")
	}

	var x BaseFieldElement
	result := new(Point)
	ok = result.V.SetFromAffineY(&y.V)
	_ = result.V.ToAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, errs.NewFailed("invalid point")
	}

	isOdd := uint64(inBytes[31] >> 7)
	if fieldsImpl.IsOdd(&x.V) != isOdd {
		result = result.Neg()
	}

	return result, nil
}

func (c *Curve) FromAffineUncompressed(inBytes []byte) (*Point, error) {
	if len(inBytes) != 2*32 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	yBytes := inBytes[:32]
	xBytes := inBytes[32:]

	var x, y BaseFieldElement
	ok := x.V.SetBytes(xBytes)
	if ok != 1 {
		return nil, errs.NewCoordinates("x")
	}
	ok = y.V.SetBytes(yBytes)
	if ok != 1 {
		return nil, errs.NewCoordinates("y")
	}

	result := new(Point)
	ok = result.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, errs.NewCoordinates("x/y")
	}

	return result, nil
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
	traits.PointTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, edwards25519Impl.Point, *Point, Point]
}

func (p *Point) HashCode() uint64 {
	//TODO implement me
	panic("implement me")
}

func (p *Point) Structure() algebra.Structure[*Point] {
	return NewCurve()
}

func (p *Point) MarshalBinary() (data []byte, err error) {
	return p.ToAffineCompressed(), nil
}

func (p *Point) UnmarshalBinary(data []byte) error {
	pp, err := NewCurve().FromAffineCompressed(data)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize point")
	}

	p.V.Set(&pp.V)
	return nil
}

// TODO(aalireza): not sure if this should always return affine coordinates or implementation defined coordinates
func (p *Point) Coordinates() []*BaseFieldElement {
	var x, y BaseFieldElement
	p.V.ToAffine(&x.V, &y.V)

	return []*BaseFieldElement{&x, &y}
}

func (p *Point) ToAffineCompressed() []byte {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)
	yBytes := y.V.Bytes()
	yBytes[31] |= byte(fieldsImpl.IsOdd(&x.V) << 7)
	return yBytes
}

func (p *Point) ToAffineUncompressed() []byte {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)

	return slices.Concat(y.V.Bytes(), x.V.Bytes())
}

func (p *Point) AffineX() *BaseFieldElement {
	if p.IsZero() {
		return NewBaseField().Zero()
	}
	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x
}

func (p *Point) AffineY() *BaseFieldElement {
	if p.IsZero() {
		return NewBaseField().One()
	}

	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y
}

func (p *Point) ScalarMul(actor *Scalar) *Point {
	var result Point
	pointsImpl.ScalarMul[*edwards25519Impl.Fp](&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *Point) IsTorsionFree() bool {
	primeOrderBytes := scalarFieldOrder.Bytes()
	slices.Reverse(primeOrderBytes)
	var e edwards25519Impl.Point
	pointsImpl.ScalarMul[*edwards25519Impl.Fp](&e, &p.V, primeOrderBytes)
	return e.IsIdentity() == 1
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
