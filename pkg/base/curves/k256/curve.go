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

func (c *Curve) FromAffineCompressed(b []byte) (*Point, error) {
	//TODO implement me
	panic("implement me")
}

func (c *Curve) FromAffineUncompressed(b []byte) (*Point, error) {
	//TODO implement me
	panic("implement me")
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

func (p *Point) Coordinates() []*BaseFieldElement {
	var x, y BaseFieldElement
	p.V.ToAffine(&x.V, &y.V)

	return []*BaseFieldElement{&x, &y}
}

func (p *Point) ToAffineCompressed() []byte {
	//TODO implement me
	panic("implement me")
}

func (p *Point) ToAffineUncompressed() []byte {
	//TODO implement me
	panic("implement me")
}

func (p *Point) AffineX() (*BaseFieldElement, error) {
	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		return nil, errs.NewFailed("failed to convert point to affine")
	}

	return &x, nil
}

func (p *Point) AffineY() (*BaseFieldElement, error) {
	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		return nil, errs.NewFailed("failed to convert point to affine")
	}

	return &y, nil
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

func (p *Point) CanBeGenerator() bool {
	//TODO implement me
	panic("implement me")
}
