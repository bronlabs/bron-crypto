package p256

import (
	"io"
	"iter"
	"reflect"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c"
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
	p256Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/p256/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

const (
	Name                  = "P256"
	Hash2CurveSuite       = "P256_XMD:SHA-256_SSWU_RO_"
	Hash2CurveScalarSuite = "P256_XMD:SHA-256_SSWU_RO_SC_"
)

var (
	p256InitOnce sync.Once
	p256Instance Curve
	p256Order    *saferith.Modulus
)

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	_ ds.Incomparable
}

func p256Init() {
	p256Order = saferith.ModulusFromBytes(bitstring.ReverseBytes(p256Impl.FqModulus[:]))

	p256Instance = Curve{}
}

func NewCurve() *Curve {
	p256InitOnce.Do(p256Init)
	return &p256Instance
}

func (*Curve) HashToFieldElements(count int, dstPrefix string, msg []byte) (u []curves.BaseFieldElement, err error) {
	out := make([]p256Impl.Fp, count)
	h2c.HashToField(out[:], p256Impl.CurveHasherParams{}, dstPrefix+Hash2CurveSuite, msg)

	u = make([]curves.BaseFieldElement, count)
	for i := range out {
		v := new(BaseFieldElement)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (*Curve) HashToScalars(count int, dstPrefix string, msg []byte) (u []curves.Scalar, err error) {
	out := make([]p256Impl.Fq, count)
	h2c.HashToField(out[:], p256Impl.CurveHasherParams{}, dstPrefix+Hash2CurveScalarSuite, msg)

	u = make([]curves.Scalar, count)
	for i := range out {
		v := new(Scalar)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (*Curve) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Contains(e curves.Point) bool {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Iter() iter.Seq[curves.Point] {
	//TODO implement me
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

func (*Curve) ElementSize() int {
	panic("implement me")
}

func (*Curve) WideElementSize() int {
	panic("implement me")
}

func (c *Curve) SuperGroupOrder() *saferith.Modulus {
	return c.Order()
}

func (*Curve) Name() string {
	return Name
}

func (c *Curve) Order() *saferith.Modulus {
	return c.SubGroupOrder()
}

func (c *Curve) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*Curve) Random(prng io.Reader) (curves.Point, error) {
	p := new(Point)
	ok := p.V.SetRandom(prng)
	if ok != 1 {
		return nil, errs.NewRandomSample("point")
	}

	return p, nil
}

func (c *Curve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuite, input)
}

func (*Curve) HashWithDst(dst string, input []byte) (curves.Point, error) {
	p := new(Point)
	p.V.Hash(dst, input)
	return p, nil
}

func (*Curve) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0p, ok0 := x0.(*Point)
	if !ok0 {
		panic("x0 is not a non-empty P256 point")
	}
	x1p, ok1 := x1.(*Point)
	if !ok1 {
		panic("x1 is not a non-empty P256 point")
	}

	p := new(Point)
	p.V.Select(choice, &x0p.V, &x1p.V)
	return p
}

// === Additive Groupoid Methods.

func (*Curve) Add(x algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Monoid Methods.

func (*Curve) AdditiveIdentity() curves.Point {
	p := new(Point)
	p.V.SetIdentity()
	return p
}

// === Group Methods.

func (*Curve) CoFactor() *saferith.Nat {
	return saferithUtils.NatOne
}

// === Additive Group Methods.

func (*Curve) Sub(x algebra.AdditiveGroupElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Cyclic Group Methods.

func (*Curve) Generator() curves.Point {
	p := new(Point)
	p.V.SetGenerator()
	return p
}

// === Variety Methods.

func (*Curve) Dimension() int {
	return 1
}

func (*Curve) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("680d8cb6fbc0a4201dd499d851c1ae23e501d15636a856b19e4ce86d8da606e5"))
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
	xx, ok := x.(*BaseFieldElement)
	if !ok {
		return nil, errs.NewType("x is not the right type")
	}
	yy, ok := y.(*BaseFieldElement)
	if !ok {
		return nil, errs.NewType("y is not the right type")
	}

	if xx.IsZero() && yy.IsZero() {
		return c.AdditiveIdentity(), nil
	}

	value := new(Point)
	ok2 := value.V.SetAffine(&xx.V, &yy.V)
	if ok2 != 1 {
		return nil, errs.NewCoordinates("could not set x,y")
	}

	return value, nil
}

// === Curve Methods.

func (c *Curve) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (*Curve) ScalarField() curves.ScalarField {
	return NewScalarField()
}

func (c *Curve) Point() curves.Point {
	return c.Element()
}

func (c *Curve) Scalar() curves.Scalar {
	return c.ScalarField().Element()
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
	//	panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	//}
	//return result
	panic("not implemented")
}

func (*Curve) TraceOfFrobenius() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("4319055358e8617b0c46353d039cdaaf"))
	return new(saferith.Int).SetNat(result)
}

func (*Curve) JInvariant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("1198954424ebb0f8479de43131caece8ee0a9b13a558c21e0b2f74e3fcd36aa3"))
	return new(saferith.Int).SetNat(result)
}

// === Prime SubGroup Methods.

func (*Curve) SubGroupOrder() *saferith.Modulus {
	return p256Order
}

func (c *Curve) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]p256Impl.Point, len(points))
	nScalars := make([][]byte, len(scalars))
	for i, pt := range points {
		ptv, ok := pt.(*Point)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointP256", reflect.TypeOf(pt).Name())
		}
		nPoints[i].Set(&ptv.V)
	}
	for i, sc := range scalars {
		s, ok := sc.(*Scalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarP256", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.V.Bytes()
	}
	value := new(Point)
	err := pointsImpl.MultiScalarMul[*p256Impl.Fp](&value.V, nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}

	return value, nil
}

func (*Curve) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*BaseFieldElement)
	if !ok {
		return nil, nil, errs.NewType("provided x coordinate is not a p256 field element")
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
