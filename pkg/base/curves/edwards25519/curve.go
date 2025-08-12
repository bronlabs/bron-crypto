package edwards25519

import (
	"hash/fnv"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	CurveName             = "edwards25519"
	Hash2CurveSuite       = "edwards25519_XMD:SHA-512_ELL2_NU_"
	Hash2CurveScalarSuite = "edwards25519_XMD:SHA-512_ELL2_NU_SC_"
	compressedPointBytes  = int(edwards25519Impl.FpBytes)
)

var (
	_ curves.EllipticCurve[*Point, *BaseFieldElement, *Scalar] = (*Curve)(nil)
	_ curves.ECPoint[*Point, *BaseFieldElement, *Scalar]       = (*Point)(nil)

	curveInstance      *Curve
	curveModelInstance *universal.ThreeSortedModel[*Point, *Scalar, *BaseFieldElement]
	curveModelInitOnce sync.Once
	curveInitOnce      sync.Once
)

type Curve struct {
	traits.CurveTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, *Point, Point]
	traits.MSMTrait[*Scalar, *Point]
}

func NewCurve() *Curve {
	curveInitOnce.Do(func() {
		curveInstance = &Curve{}
	})

	return curveInstance
}

func CurveModel() *universal.ThreeSortedModel[*Point, *Scalar, *BaseFieldElement] {
	curveModelInitOnce.Do(func() {
		var err error
		curveModelInstance, err = impl.EllipticCurveModel(
			NewCurve(), NewBaseField(), NewScalarField(),
		)
		if err != nil {
			panic(err)
		}
	})

	return curveModelInstance
}

func (c *Curve) Name() string {
	return CurveName
}

func (c *Curve) Model() *universal.Model[*Point] {
	return CurveModel().First()
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
	return cardinal.New(8)
}

func (c *Curve) Order() cardinal.Cardinal {
	return cardinal.NewFromNat(scalarFieldOrder.Nat())
}

func (c *Curve) FromCompressed(inBytes []byte) (*Point, error) {
	if len(inBytes) != int(compressedPointBytes) {
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

	isOdd := ct.Bool(inBytes[31] >> 7)
	if fieldsImpl.IsOdd(&x.V) != isOdd {
		result = result.Neg()
	}

	return result, nil
}

func (c *Curve) FromBytes(input []byte) (*Point, error) {
	return c.FromCompressed(input)
}

func (c *Curve) FromUncompressed(inBytes []byte) (*Point, error) {
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

func (c *Curve) Hash(bytes []byte) (*Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuite, bytes)
}

func (c *Curve) HashWithDst(dst string, bytes []byte) (*Point, error) {
	var p Point
	p.V.Hash(dst, bytes)
	return &p, nil
}

func (c *Curve) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (c *Curve) BaseStructure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

type Point struct {
	traits.PointTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, edwards25519Impl.Point, *Point, Point]
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
	return algebra.NewCoordinates(
		algebra.AffineCoordinateSystem,
		&x, &y,
	)
}

func (p *Point) ToCompressed() []byte {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)
	yBytes := y.V.Bytes()
	yBytes[31] |= byte(fieldsImpl.IsOdd(&x.V) << 7)
	return yBytes
}

func (p *Point) ToUncompreseed() []byte {
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

func (p *Point) ScalarOp(sc *Scalar) *Point {
	return p.ScalarMul(sc)
}

func (p *Point) ScalarMul(actor *Scalar) *Point {
	var result Point
	aimpl.ScalarMul(&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *Point) IsTorsionFree() bool {
	primeOrderBytes := scalarFieldOrder.Bytes()
	slices.Reverse(primeOrderBytes)
	var e edwards25519Impl.Point
	aimpl.ScalarMul(&e, &p.V, primeOrderBytes)
	return e.IsZero() == 1
}

func (p *Point) Bytes() []byte {
	return p.ToCompressed()
}

func (p *Point) String() string {
	return traits.StringifyPoint(p)
}
