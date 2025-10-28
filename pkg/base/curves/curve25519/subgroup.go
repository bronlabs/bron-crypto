package curve25519

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	PrimeCurveName = CurveName + "(PrimeSubGroup)"
)

var (
	_ curves.Curve[*PrimeSubGroupPoint, *BaseFieldElement, *Scalar] = (*PrimeSubGroup)(nil)
	_ curves.Point[*PrimeSubGroupPoint, *BaseFieldElement, *Scalar] = (*PrimeSubGroupPoint)(nil)

	primeSubGroupInstance *PrimeSubGroup
	primeSubGroupInitOnce sync.Once
)

func NewPrimeSubGroup() *PrimeSubGroup {
	primeSubGroupInitOnce.Do(func() {
		primeSubGroupInstance = &PrimeSubGroup{}
	})

	return primeSubGroupInstance
}

type PrimeSubGroup struct {
	traits.PrimeCurveTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, *PrimeSubGroupPoint, PrimeSubGroupPoint]
	traits.MSMTrait[*Scalar, *PrimeSubGroupPoint]
}

func (c *PrimeSubGroup) Name() string {
	return PrimeCurveName
}

func (c *PrimeSubGroup) ElementSize() int {
	return 32
}

func (c *PrimeSubGroup) Cofactor() cardinal.Cardinal {
	return cardinal.New(8)
}

func (c *PrimeSubGroup) Order() cardinal.Cardinal {
	return NewScalarField().Order()
}

func (c *PrimeSubGroup) FromCompressed(data []byte) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().FromCompressed(data)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize point")
	}
	return p.AsPrimeSubGroupPoint()
}

func (c *PrimeSubGroup) FromBytes(data []byte) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().FromBytes(data)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize point")
	}
	return p.AsPrimeSubGroupPoint()
}

func (c *PrimeSubGroup) FromUncompressed(data []byte) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().FromUncompressed(data)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize point")
	}
	return p.AsPrimeSubGroupPoint()
}

func (c *PrimeSubGroup) FromAffine(x, y *BaseFieldElement) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().FromAffine(x, y)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set coordinates")
	}
	return p.AsPrimeSubGroupPoint()
}

func (c *PrimeSubGroup) Hash(bytes []byte) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().Hash(bytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash to curve")
	}
	return p.AsPrimeSubGroupPoint()
}

func (c *PrimeSubGroup) HashWithDst(dst string, bytes []byte) (*PrimeSubGroupPoint, error) {
	p, err := NewCurve().HashWithDst(dst, bytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash to curve")
	}
	return p.AsPrimeSubGroupPoint()
}

func (c *PrimeSubGroup) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (c *PrimeSubGroup) ScalarRing() algebra.ZModLike[*Scalar] {
	return NewScalarField()
}

func (c *PrimeSubGroup) ScalarField() algebra.PrimeField[*Scalar] {
	return NewScalarField()
}

func (c *PrimeSubGroup) BaseField() algebra.FiniteField[*BaseFieldElement] {
	return NewBaseField()
}

func (c *PrimeSubGroup) BaseStructure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

func (c *PrimeSubGroup) ScalarBaseOp(sc *Scalar) *PrimeSubGroupPoint {
	return c.ScalarBaseMul(sc)
}

func (c *PrimeSubGroup) ScalarBaseMul(sc *Scalar) *PrimeSubGroupPoint {
	return c.Generator().ScalarMul(sc)
}

type PrimeSubGroupPoint struct {
	traits.PrimePointTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, edwards25519Impl.Point, *PrimeSubGroupPoint, PrimeSubGroupPoint]
}

func (p *PrimeSubGroupPoint) HashCode() base.HashCode {
	return p.AsPoint().HashCode()
}

func (p *PrimeSubGroupPoint) Structure() algebra.Structure[*PrimeSubGroupPoint] {
	return NewPrimeSubGroup()
}

func (p PrimeSubGroupPoint) Coordinates() algebra.Coordinates[*BaseFieldElement] {
	return p.AsPoint().Coordinates()
}

func (p *PrimeSubGroupPoint) ToCompressed() []byte {
	return p.AsPoint().ToCompressed()
}

func (p *PrimeSubGroupPoint) ToUncompressed() []byte {
	return p.AsPoint().ToUncompressed()
}

func (p *PrimeSubGroupPoint) AffineX() (*BaseFieldElement, error) {
	return p.AsPoint().AffineX()
}

func (p *PrimeSubGroupPoint) AffineY() (*BaseFieldElement, error) {
	return p.AsPoint().AffineY()
}

func (p *PrimeSubGroupPoint) ScalarOp(sc *Scalar) *PrimeSubGroupPoint {
	return p.ScalarMul(sc)
}

func (p *PrimeSubGroupPoint) ScalarMul(actor *Scalar) *PrimeSubGroupPoint {
	var result PrimeSubGroupPoint
	aimpl.ScalarMul(&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *PrimeSubGroupPoint) IsTorsionFree() bool {
	return true
}

func (p *PrimeSubGroupPoint) Bytes() []byte {
	return p.AsPoint().ToCompressed()
}

func (p *PrimeSubGroupPoint) String() string {
	return p.AsPoint().String()
}

func (p *PrimeSubGroupPoint) AsPoint() *Point {
	var pp Point
	pp.V.Set(&p.V)
	return &pp
}
