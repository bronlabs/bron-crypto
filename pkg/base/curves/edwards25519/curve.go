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
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	CurveName             = "edwards25519"
	Hash2CurveSuite       = "edwards25519_XMD:SHA-512_ELL2_NU_"
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
	return NewScalarField().Order()
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

func (c *Curve) FromAffine(x, y *BaseFieldElement) (*Point, error) {
	var p Point
	ok := p.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, errs.NewCoordinates("x/y")
	}
	return &p, nil
}

func (c *Curve) Hash(bytes []byte) (*Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuite, bytes)
}

func (c *Curve) HashWithDst(dst string, bytes []byte) (*Point, error) {
	var p Point
	p.V.Hash(dst, bytes)
	return &p, nil
}

func (c *Curve) ScalarRing() algebra.ZModLike[*Scalar] {
	return NewScalarField()
}

func (c *Curve) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (c *Curve) BaseStructure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

func (c *Curve) BaseField() algebra.FiniteField[*BaseFieldElement] {
	return NewBaseField()
}

func (c *Curve) MultiScalarOp(scalars []*Scalar, points []*Point) (*Point, error) {
	return c.MultiScalarMul(scalars, points)
}

func (c *Curve) MultiScalarMul(scalars []*Scalar, points []*Point) (*Point, error) {
	if len(scalars) != len(points) {
		return nil, errs.NewLength("mismatched lengths of scalars and points")
	}
	var result Point
	scs := make([][]byte, len(scalars))
	pts := make([]*edwards25519Impl.Point, len(points))
	for i := range points {
		pts[i] = &points[i].V
		scs[i] = scalars[i].Bytes()
	}
	aimpl.MultiScalarMulLowLevel(&result.V, pts, scs)
	return &result, nil
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

func (p *Point) ToCompressed() []byte {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)
	yBytes := y.V.Bytes()
	yBytes[31] |= byte(fieldsImpl.IsOdd(&x.V) << 7)
	return yBytes
}

func (p *Point) ToUncompressed() []byte {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)

	return slices.Concat(y.V.Bytes(), x.V.Bytes())
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
	aimpl.ScalarMulLowLevel(&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *Point) IsTorsionFree() bool {
	primeOrderBytes := NewScalarField().Order().Bytes()
	slices.Reverse(primeOrderBytes)
	var e edwards25519Impl.Point
	aimpl.ScalarMulLowLevel(&e, &p.V, primeOrderBytes)
	return e.IsZero() == 1
}

func (p *Point) Bytes() []byte {
	return p.ToCompressed()
}

func (p *Point) String() string {
	if p.IsZero() {
		return "(0, 1, 0, 1)"
	} else {
		return fmt.Sprintf("(%s, %s, %s, %s)", p.V.X.String(), p.V.Y.String(), p.V.T.String(), p.V.Z.String())
	}
}

func (p *Point) AsPrimeSubGroupPoint() (*PrimeSubGroupPoint, error) {
	if !p.IsTorsionFree() {
		return nil, errs.NewFailed("point is not in the prime subgroup")
	}

	var pp PrimeSubGroupPoint
	pp.V.Set(&p.V)
	return &pp, nil
}
