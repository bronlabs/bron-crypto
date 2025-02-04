package k256

import (
	"io"
	"iter"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c"
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
	k256Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/k256/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

const (
	Name                  = "secp256k1"
	Hash2CurveSuite       = "secp256k1_XMD:SHA-256_SSWU_RO_"
	Hash2CurveScalarSuite = "secp256k1_XMD:SHA-256_SSWU_RO_SC_"
)

var (
	k256InitOnce sync.Once
	k256Instance Curve
	k256Order    *saferith.Modulus

	traceOfFrobenius, _ = new(saferith.Nat).SetHex(strings.ToUpper("14551231950b75fc4402da1722fc9baef"))
	jInvariant          = new(saferith.Nat).SetUint64(0)
)

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	_ ds.Incomparable
}

func k256Init() {
	k256Order = saferith.ModulusFromBytes(bitstring.ReverseBytes(k256Impl.FqModulus[:]))

	k256Instance = Curve{}
}

func NewCurve() *Curve {
	k256InitOnce.Do(k256Init)
	return &k256Instance
}

func (*Curve) HashToFieldElements(count int, dstPrefix string, msg []byte) (u []curves.BaseFieldElement, err error) {
	out := make([]k256Impl.Fp, count)
	h2c.HashToField(out[:], k256Impl.CurveHasherParams{}, dstPrefix+Hash2CurveSuite, msg)

	u = make([]curves.BaseFieldElement, count)
	for i := range out {
		v := new(BaseFieldElement)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (*Curve) HashToScalars(count int, dstPrefix string, msg []byte) (u []curves.Scalar, err error) {
	out := make([]k256Impl.Fq, count)
	h2c.HashToField(out[:], k256Impl.CurveHasherParams{}, dstPrefix+Hash2CurveScalarSuite, msg)

	u = make([]curves.Scalar, count)
	for i := range out {
		v := new(Scalar)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (c *Curve) Cardinality() *saferith.Nat {
	return c.Order().Nat()
}

func (*Curve) Contains(e curves.Point) bool {
	return e.IsInPrimeSubGroup()
}

func (*Curve) Iter() iter.Seq[curves.Point] {
	panic("implement me")
}

func (*Curve) Operators() []algebra.BinaryOperator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (c *Curve) Unwrap() curves.Curve {
	return c
}

func (*Curve) IsDefinedUnder(operator algebra.BinaryOperator[curves.Point]) bool {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Op(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], ys ...algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Addition() algebra.Addition[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*Curve) ModuleScalarRing() algebra.ModuleBaseRing[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*Curve) AlgebraicVarietyBaseField() algebra.AlgebraicVarietyBaseField[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*Curve) VectorSpaceScalarField() algebra.VectorSpaceBaseField[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (c *Curve) BasePoint() curves.Point {
	return c.Generator()
}

func (*Curve) DLog(b, x algebra.CyclicGroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (c *Curve) SuperGroupOrder() *saferith.Modulus {
	return c.Order()
}

func (*Curve) ElementSize() int {
	panic("implement me")
}

func (*Curve) WideElementSize() int {
	panic("implement me")
}

func (*Curve) Name() string {
	return Name
}

func (*Curve) Order() *saferith.Modulus {
	return k256Order
}

func (c *Curve) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*Curve) Random(prng io.Reader) (curves.Point, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}

	p := new(Point)
	ok := p.V.SetRandom(prng)
	if ok != 1 {
		return nil, errs.NewRandomSample("cannot sample random point")
	}

	return p, nil
}

func (c *Curve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuite, input)
}

func (*Curve) HashWithDst(dst string, msg []byte) (curves.Point, error) {
	p := new(Point)
	p.V.Hash(dst, msg)
	return p, nil
}

func (*Curve) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0p, ok0 := x0.(*Point)
	if !ok0 {
		panic("x0 is not a non-empty K256 point")
	}
	x1p, ok1 := x1.(*Point)
	if !ok1 {
		panic("x1 is not a non-empty K256 point")
	}

	p := new(Point)
	p.V.Select(choice, &x0p.V, &x1p.V)
	return p
}

func (*Curve) Add(x algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Monoid Methods.

func (*Curve) AdditiveIdentity() curves.Point {
	id := new(Point)
	id.V.SetIdentity()
	return id
}

func (*Curve) CoFactor() *saferith.Nat {
	return saferithUtils.NatOne
}

func (*Curve) Sub(x algebra.AdditiveGroupElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

func (*Curve) Generator() curves.Point {
	gen := new(Point)
	gen.V.SetGenerator()
	return gen
}

func (*Curve) Dimension() int {
	return 1
}

func (*Curve) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffa97f"))
	return new(saferith.Int).SetNat(result)
}

// === Algebraic Curve Methods.

func (*Curve) BaseField() curves.BaseField {
	return NewBaseField()
}

func (c *Curve) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}
	xx, ok := x.Unwrap().(*BaseFieldElement)
	if !ok {
		return nil, errs.NewType("x is not the right type")
	}
	yy, ok := y.Unwrap().(*BaseFieldElement)
	if !ok {
		return nil, errs.NewType("y is not the right type")
	}

	value := new(Point)
	ok2 := value.V.SetAffine(&xx.V, &yy.V)
	if ok2 != 1 {
		return c.AdditiveIdentity(), nil
	}

	return value, nil
}

// === Elliptic Curve Methods.

func (*Curve) ScalarField() curves.ScalarField {
	return NewScalarField()
}

func (c *Curve) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (c *Curve) Point() curves.Point {
	return c.AdditiveIdentity()
}

func (c *Curve) Scalar() curves.Scalar {
	return c.ScalarField().AdditiveIdentity()
}

func (c *Curve) BaseFieldElement() curves.BaseFieldElement {
	return c.BaseField().Zero()
}

func (*Curve) FrobeniusEndomorphism(p curves.Point) curves.Point {
	//pp, ok := p.(*Point)
	//if !ok {
	//	panic("given point is not of the right type")
	//}
	//x := pp.AffineX()
	//y := pp.AffineY()
	//characteristic := NewBaseFieldElement(0).SetNat(NewBaseField().Characteristic())
	//result, err := c.NewPoint(x.Exp(characteristic.Nat()), y.Exp(characteristic.Nat()))
	//if err != nil {
	//	panic(errs.WrapFailed(err, "frobenius endomorphism did not succeed"))
	//}
	//return result
	panic("not implemented")
}

func (*Curve) TraceOfFrobenius() *saferith.Int {
	return new(saferith.Int).SetNat(traceOfFrobenius)
}

func (*Curve) JInvariant() *saferith.Int {
	return new(saferith.Int).SetNat(jInvariant)
}

// === Prime SubGroup Methods.

func (c *Curve) SubGroupOrder() *saferith.Modulus {
	return c.Order()
}

func (c *Curve) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]k256Impl.Point, len(points))
	nScalars := make([][]byte, len(scalars))
	for i, pt := range points {
		ptv, ok := pt.(*Point)
		if !ok {
			return nil, errs.NewFailed("invalid point type, expected PointK256")
		}
		nPoints[i].Set(&ptv.V)
	}
	for i, sc := range scalars {
		s, ok := sc.(*Scalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type, expected ScalarK256")
		}
		nScalars[i] = s.V.Bytes()
	}

	var value = new(Point)
	err := pointsImpl.MultiScalarMul[*k256Impl.Fp](&value.V, nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}
	return value, nil
}

func (*Curve) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*BaseFieldElement)
	if !ok {
		return nil, nil, errs.NewType("provided x coordinate is not a k256 field element")
	}

	p1 := new(Point)
	p1.V.SetFromAffineX(&xc.V)
	p2 := new(Point)
	p2.V.Neg(&p1.V)
	if p1.AffineY().IsEven() {
		return p1, p2, nil
	}
	return p2, p1, nil
}
