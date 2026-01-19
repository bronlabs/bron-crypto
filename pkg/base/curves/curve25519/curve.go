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
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

const (
	// CurveName is the curve name.
	CurveName = "curve25519"
	// Hash2CurveSuite is the hash-to-curve suite string.
	Hash2CurveSuite = "curve25519_XMD:SHA-512_ELL2_NU_"
)

var (
	_ curves.EllipticCurve[*Point, *BaseFieldElement, *Scalar] = (*Curve)(nil)
	_ curves.ECPoint[*Point, *BaseFieldElement, *Scalar]       = (*Point)(nil)

	curveInstance *Curve
	curveInitOnce sync.Once

	c edwards25519Impl.Fp
)

//nolint:gochecknoinits // init c
func init() {
	c.MustSetHex("0f26edf460a006bbd27b08dc03fc4f7ec5a1d3d14b7d1a82cc6e04aaff457e06")
}

// Curve represents the elliptic curve group.
type Curve struct {
	traits.CurveTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, *Point, Point]
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

// Cofactor returns the curve cofactor.
func (*Curve) Cofactor() cardinal.Cardinal {
	return cardinal.New(8)
}

// Order returns the group or field order.
func (*Curve) Order() cardinal.Cardinal {
	return NewScalarField().Order()
}

// ElementSize returns the element size in bytes.
func (*Curve) ElementSize() int {
	return edwards25519Impl.FpBytes
}

// FromCompressed decodes a compressed point.
func (c *Curve) FromCompressed(data []byte) (*Point, error) {
	if len(data) != 32 {
		return nil, curves.ErrInvalidLength.WithMessage("invalid byte sequence")
	}
	if sliceutils.All(data, func(b byte) bool { return b == 0 }) {
		return c.OpIdentity(), nil
	}

	var one, u edwards25519Impl.Fp
	one.SetOne()
	ok := u.SetBytes(data)
	if ok == ct.False {
		return nil, curves.ErrFailed.WithMessage("invalid compressed point")
	}

	var n, d, dInv, y edwards25519Impl.Fp
	n.Sub(&u, &one)
	d.Add(&u, &one)
	ok = dInv.Inv(&d)
	if ok == ct.False {
		return nil, curves.ErrFailed.WithMessage("invalid compressed point")
	}
	y.Mul(&n, &dInv)

	var p Point
	ok = p.V.SetFromAffineY(&y)
	if ok == ct.False {
		return nil, curves.ErrFailed.WithMessage("invalid compressed point")
	}
	return &p, nil
}

// FromBytes decodes an element from bytes.
func (c *Curve) FromBytes(input []byte) (*Point, error) {
	return c.FromCompressed(input)
}

// FromUncompressed decodes an uncompressed point.
func (c *Curve) FromUncompressed(data []byte) (*Point, error) {
	if len(data) != 64 {
		return nil, curves.ErrInvalidLength.WithMessage("invalid byte sequence")
	}
	if sliceutils.All(data, func(b byte) bool { return b == 0 }) {
		return c.OpIdentity(), nil
	}

	xBytes := data[:32]
	yBytes := data[32:]
	var x, y BaseFieldElement
	ok := x.V.SetBytes(xBytes)
	if ok == ct.False {
		return nil, curves.ErrFailed.WithMessage("invalid uncompressed point")
	}
	ok = y.V.SetBytes(yBytes)
	if ok == ct.False {
		return nil, curves.ErrFailed.WithMessage("invalid uncompressed point")
	}
	return c.FromAffine(&x, &y)
}

// FromAffine builds a point from affine coordinates.
func (c *Curve) FromAffine(x, y *BaseFieldElement) (*Point, error) {
	p, err := c.FromCompressed(x.V.Bytes())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot deserialize point")
	}

	y2, err := p.AffineY()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot deserialize point")
	}
	if y.Equal(y2) {
		return p, nil
	}

	p = p.Neg()
	y2, err = p.AffineY()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot deserialize point")
	}
	if y.Equal(y2) {
		return p, nil
	}

	return nil, curves.ErrFailed.WithMessage("cannot deserialize point")
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

// ScalarStructure returns the scalar structure.
func (*Curve) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

// ScalarRing returns the scalar ring.
func (*Curve) ScalarRing() algebra.ZModLike[*Scalar] {
	return NewScalarField()
}

// BaseStructure returns the base field structure.
func (*Curve) BaseStructure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

// BaseField returns the base field.
func (*Curve) BaseField() algebra.FiniteField[*BaseFieldElement] {
	return NewBaseField()
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
	pts := make([]*edwards25519Impl.Point, len(points))
	for i := range points {
		pts[i] = &points[i].V
		scs[i] = scalars[i].V.Bytes()
	}
	aimpl.MultiScalarMulLowLevel(&result.V, pts, scs)
	return &result, nil
}

// Point represents a curve point.
type Point struct {
	traits.PointTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, edwards25519Impl.Point, *Point, Point]
}

// AffineX returns the affine x-coordinate.
func (p *Point) AffineX() (*BaseFieldElement, error) {
	var u, w, wInv edwards25519Impl.Fp
	u.Add(&p.V.Z, &p.V.Y)
	w.Sub(&p.V.Z, &p.V.Y)
	ok := wInv.Inv(&w)
	if ok == 0 {
		return nil, curves.ErrFailed.WithMessage("cannot get affine x")
	}

	var bfe BaseFieldElement
	bfe.V.Mul(&u, &wInv)
	return &bfe, nil
}

// AffineY returns the affine y-coordinate.
func (p *Point) AffineY() (*BaseFieldElement, error) {
	var u, w, wInv edwards25519Impl.Fp
	u.Add(&p.V.Z, &p.V.Y)
	w.Sub(&p.V.X, &p.V.T)
	ok := wInv.Inv(&w)
	if ok == 0 {
		return nil, curves.ErrFailed.WithMessage("cannot get affine y")
	}

	var bfe BaseFieldElement
	bfe.V.Mul(&u, &wInv)
	bfe.V.Mul(&bfe.V, &c)
	return &bfe, nil
}

// ToCompressed encodes the point in compressed form.
func (p *Point) ToCompressed() []byte {
	if p.IsOpIdentity() {
		return make([]byte, 32)
	}

	x, err := p.AffineX()
	if err != nil {
		panic(errs2.Wrap(err).WithMessage("this should never happen"))
	}

	return x.V.Bytes()
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

// ToUncompressed encodes the point in uncompressed form.
func (p *Point) ToUncompressed() []byte {
	if p.IsOpIdentity() {
		return make([]byte, 64)
	}

	x, err := p.AffineX()
	if err != nil {
		panic(errs2.Wrap(err).WithMessage("this should never happen"))
	}
	y, err := p.AffineY()
	if err != nil {
		panic(errs2.Wrap(err).WithMessage("this should never happen"))
	}

	return append(x.V.Bytes(), y.V.Bytes()...)
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
	primeOrderBytes := NewScalarField().Order().Bytes()
	slices.Reverse(primeOrderBytes)
	var e edwards25519Impl.Point
	aimpl.ScalarMulLowLevel(&e, &p.V, primeOrderBytes)
	return e.IsZero() != ct.False
}

// Bytes returns the canonical byte encoding.
func (p *Point) Bytes() []byte {
	return p.ToCompressed()
}

// String returns the string form of the receiver.
func (p *Point) String() string {
	xBytes := p.ToCompressed()
	slices.Reverse(xBytes)
	xInt := new(big.Int).SetBytes(xBytes)

	return fmt.Sprintf("(%s)", xInt.Text(10))
}

// AsPrimeSubGroupPoint converts to a prime subgroup point if torsion-free.
func (p *Point) AsPrimeSubGroupPoint() (*PrimeSubGroupPoint, error) {
	if !p.IsTorsionFree() {
		return nil, curves.ErrFailed.WithMessage("point is not in the prime subgroup")
	}

	var pp PrimeSubGroupPoint
	pp.V.Set(&p.V)
	return &pp, nil
}
