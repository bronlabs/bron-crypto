package curve25519

import (
	"fmt"
	"hash/fnv"
	"math/big"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

const (
	CurveName       = "curve25519"
	Hash2CurveSuite = "curve25519_XMD:SHA-512_ELL2_NU_"
)

var (
	_ curves.EllipticCurve[*Point, *BaseFieldElement, *Scalar] = (*Curve)(nil)
	_ curves.ECPoint[*Point, *BaseFieldElement, *Scalar]       = (*Point)(nil)

	curveInstance *Curve
	curveInitOnce sync.Once

	c edwards25519Impl.Fp
)

func init() {
	c.MustSetHex("0f26edf460a006bbd27b08dc03fc4f7ec5a1d3d14b7d1a82cc6e04aaff457e06")
}

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

func (c *Curve) Cofactor() cardinal.Cardinal {
	return cardinal.New(8)
}

func (c *Curve) Order() cardinal.Cardinal {
	return NewScalarField().Order()
}

func (c *Curve) ElementSize() int {
	return edwards25519Impl.FpBytes
}

func (c *Curve) FromCompressed(data []byte) (*Point, error) {
	if len(data) != 32 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	if sliceutils.All(data, func(b byte) bool { return b == 0 }) {
		return c.OpIdentity(), nil
	}

	var one, u edwards25519Impl.Fp
	one.SetOne()
	ok := u.SetBytes(data)
	if ok == ct.False {
		return nil, errs.NewFailed("invalid compressed point")
	}

	var n, d, dInv, y edwards25519Impl.Fp
	n.Sub(&u, &one)
	d.Add(&u, &one)
	ok = dInv.Inv(&d)
	if ok == ct.False {
		return nil, errs.NewFailed("invalid compressed point")
	}
	y.Mul(&n, &dInv)

	var p Point
	ok = p.V.SetFromAffineY(&y)
	if ok == ct.False {
		return nil, errs.NewFailed("invalid compressed point")
	}
	return &p, nil
}

func (c *Curve) FromBytes(input []byte) (*Point, error) {
	return c.FromCompressed(input)
}

func (c *Curve) FromUncompressed(data []byte) (*Point, error) {
	if len(data) != 64 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	if sliceutils.All(data, func(b byte) bool { return b == 0 }) {
		return c.OpIdentity(), nil
	}

	xBytes := data[:32]
	yBytes := data[32:]
	var x, y BaseFieldElement
	ok := x.V.SetBytes(xBytes)
	if ok == ct.False {
		return nil, errs.NewFailed("invalid uncompressed point")
	}
	ok = y.V.SetBytes(yBytes)
	if ok == ct.False {
		return nil, errs.NewFailed("invalid uncompressed point")
	}
	return c.FromAffine(&x, &y)
}

func (c *Curve) FromAffine(x, y *BaseFieldElement) (*Point, error) {
	p, err := c.FromCompressed(x.V.Bytes())
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize point")
	}

	y2, err := p.AffineY()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize point")
	}
	if y.Equal(y2) {
		return p, nil
	}

	p = p.Neg()
	y2, err = p.AffineY()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize point")
	}
	if y.Equal(y2) {
		return p, nil
	}

	return nil, errs.NewFailed("cannot deserialize point")
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

func (c *Curve) ScalarRing() algebra.ZModLike[*Scalar] {
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

func (p *Point) AffineX() (*BaseFieldElement, error) {
	var u, w, wInv edwards25519Impl.Fp
	u.Add(&p.V.Z, &p.V.Y)
	w.Sub(&p.V.Z, &p.V.Y)
	ok := wInv.Inv(&w)
	if ok == 0 {
		return nil, errs.NewFailed("cannot get affine x")
	}

	var bfe BaseFieldElement
	bfe.V.Mul(&u, &wInv)
	return &bfe, nil
}

func (p *Point) AffineY() (*BaseFieldElement, error) {
	var u, w, wInv edwards25519Impl.Fp
	u.Add(&p.V.Z, &p.V.Y)
	w.Sub(&p.V.X, &p.V.T)
	ok := wInv.Inv(&w)
	if ok == 0 {
		return nil, errs.NewFailed("cannot get affine y")
	}

	var bfe BaseFieldElement
	bfe.V.Mul(&u, &wInv)
	bfe.V.Mul(&bfe.V, &c)
	return &bfe, nil
}

func (p *Point) ToCompressed() []byte {
	if p.IsOpIdentity() {
		return make([]byte, 32)
	}

	x, err := p.AffineX()
	if err != nil {
		panic(errs.WrapFailed(err, "this should never happen"))
	}

	return x.V.Bytes()
}

func (p *Point) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

func (p *Point) Structure() algebra.Structure[*Point] {
	return NewCurve()
}

func (p *Point) ToUncompressed() []byte {
	if p.IsOpIdentity() {
		return make([]byte, 64)
	}

	x, err := p.AffineX()
	if err != nil {
		panic(errs.WrapFailed(err, "this should never happen"))
	}
	y, err := p.AffineY()
	if err != nil {
		panic(errs.WrapFailed(err, "this should never happen"))
	}

	return append(x.V.Bytes(), y.V.Bytes()...)
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
	return e.IsZero() != ct.False
}

func (p *Point) Bytes() []byte {
	return p.ToCompressed()
}

func (p *Point) String() string {
	xBytes := p.ToCompressed()
	slices.Reverse(xBytes)
	xInt := new(big.Int).SetBytes(xBytes)

	return fmt.Sprintf("(%s)", xInt.Text(10))
}

func (p *Point) AsPrimeSubGroupPoint() (*PrimeSubGroupPoint, error) {
	if !p.IsTorsionFree() {
		return nil, errs.NewFailed("point is not in the prime subgroup")
	}

	var pp PrimeSubGroupPoint
	pp.V.Set(&p.V)
	return &pp, nil
}
