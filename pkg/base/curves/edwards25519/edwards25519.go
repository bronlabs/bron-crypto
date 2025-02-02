package edwards25519

import (
	"io"
	"iter"
	"reflect"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519/impl"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c"
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

const (
	Name                   = "edwards25519"
	HashToCurveSuite       = "edwards25519_XMD:SHA-512_ELL2_RO_"
	HashToCurveScalarSuite = "edwards25519_XMD:SHA-512_ELL2_RO_SC_"
)

var (
	edwards25519InitOnce sync.Once
	edwards25519Instance Curve

	subgroupOrder, _  = saferith.ModulusFromHex(strings.ToUpper("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"))
	cofactor          = new(saferith.Nat).SetUint64(8)
	groupOrder        = saferith.ModulusFromNat(new(saferith.Nat).Mul(subgroupOrder.Nat(), cofactor, subgroupOrder.Nat().AnnouncedLen()+cofactor.AnnouncedLen()))
	baseFieldOrder, _ = saferith.ModulusFromHex(strings.ToUpper("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"))
	elementSize       = 32
)

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	_ ds.Incomparable
}

func ed25519Init() {
	edwards25519Instance = Curve{}
}

func NewCurve() *Curve {
	edwards25519InitOnce.Do(ed25519Init)
	return &edwards25519Instance
}

func (*Curve) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Contains(e curves.Point) bool {
	return true
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
	return elementSize
}

func (*Curve) WideElementSize() int {
	panic("implement me")
}

func (*Curve) SuperGroupOrder() *saferith.Modulus {
	return groupOrder
}

func (*Curve) Name() string {
	return Name
}

func (*Curve) Order() *saferith.Modulus {
	return subgroupOrder
}

func (c *Curve) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*Curve) Random(prng io.Reader) (curves.Point, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}

	result := new(Point)
	ok := result.V.SetRandom(prng)
	if ok != 1 {
		return nil, errs.NewRandomSample("point")
	}

	return result, nil
}

func (c *Curve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+HashToCurveSuite, nil)
}

func (*Curve) HashWithDst(dst string, input []byte) (curves.Point, error) {
	result := new(Point)
	result.V.Hash(dst, input)
	return result, nil
}

func (*Curve) HashToFieldElements(count int, dstPrefix string, msg []byte) (u []curves.BaseFieldElement, err error) {
	out := make([]edwards25519Impl.Fp, count)
	h2c.HashToField(out[:], edwards25519Impl.CurveHasherParams{}, dstPrefix+HashToCurveSuite, msg)

	u = make([]curves.BaseFieldElement, count)
	for i := range out {
		v := new(BaseFieldElement)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (*Curve) HashToScalars(count int, dstPrefix string, msg []byte) (u []curves.Scalar, err error) {
	out := make([]edwards25519Impl.Fq, count)
	h2c.HashToField(out[:], edwards25519Impl.CurveHasherParams{}, dstPrefix+HashToCurveScalarSuite, msg)

	u = make([]curves.Scalar, count)
	for i := range out {
		v := new(Scalar)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (*Curve) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0Ed, ok0 := x0.(*Point)
	if !ok0 {
		panic("x0 is not a non-empty edwards25519 point")
	}
	x1Ed, ok1 := x1.(*Point)
	if !ok1 {
		panic("x1 is not a non-empty edwards25519 point")
	}

	result := new(Point)
	result.V.Select(choice, &x0Ed.V, &x1Ed.V)
	return result
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

func (*Curve) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("not implemented")
}

// === Additive Monoid Methods.

func (*Curve) AdditiveIdentity() curves.Point {
	result := new(Point)
	result.V.SetIdentity()
	return result
}

// === Group Methods.

func (*Curve) CoFactor() *saferith.Nat {
	return new(saferith.Nat).SetUint64(8)
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
	result := new(Point)
	result.V.SetGenerator()
	return result
}

// === Variety Methods.

func (*Curve) Dimension() int {
	return 1
}

func (*Curve) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("1562fe9d5c16b700e197a60c9a6c11c0eb738987971858db4bfc83e985be241"))
	return new(saferith.Int).SetNat(result)
}

// === Algebraic Curve Methods.

func (*Curve) BaseField() curves.BaseField {
	return NewBaseField()
}

func (*Curve) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
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

	result := new(Point)
	if xx.V.IsZero() == 1 && yy.V.IsZero() == 1 {
		result.V.SetIdentity()
		return result, nil
	}

	ok2 := result.V.SetAffine(&xx.V, &yy.V)
	if ok2 != 1 {
		return nil, errs.NewFailed("cannot create point")
	}

	return result, nil
}

// === Elliptic Curve Methods.

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
	panic("not implemented")
}

func (*Curve) TraceOfFrobenius() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("56c143fbfba334948229e71bacc4801f4321f1a7c4591336f27d7903cb215317"))
	return new(saferith.Int).SetNat(result)
}

func (*Curve) JInvariant() *saferith.Int {
	v, _ := new(saferith.Nat).SetHex(strings.ToUpper("a6f7cef517bce6b2c09318d2e7ae9f7a"))
	return new(saferith.Int).SetNat(v).Neg(1)
}

// === Prime SubGroup Methods.

func (*Curve) SubGroupOrder() *saferith.Modulus {
	return subgroupOrder
}

func (c *Curve) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	scalar, ok := sc.(*Scalar)
	if !ok {
		panic("scalar is not of type edwards25519 Scalar")
	}

	return c.Generator().ScalarMul(scalar)
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]edwards25519Impl.Point, len(points))
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
	err := pointsImpl.MultiScalarMul[*edwards25519Impl.Fp](&value.V, nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}

	return value, nil
}

func (*Curve) DeriveFromAffineX(x curves.BaseFieldElement) (p1, p2 curves.Point, err error) {
	//xc, ok := x.(*BaseFieldElement)
	//if !ok {
	//	return nil, nil, errs.NewType("x is not an edwards25519 base field element")
	//}
	//
	//feOne := new(filippo_field.Element).One()
	//
	//// -x² + y² = 1 + dx²y²
	//// x² + dx²y² = x²(dy² + 1) = y² - 1
	//// y² = (x² + 1) / (1 - dx²)
	//
	//// u = x² + 1
	//x2 := new(filippo_field.Element).Square(xc.V)
	//u := new(filippo_field.Element).Add(x2, feOne)
	//
	//// v = 1 - dx²
	//dx2 := new(filippo_field.Element).Multiply(x2, d)
	//v := dx2.Subtract(feOne, dx2)
	//
	//// x = +√(u/v)
	//y, wasSquare := new(filippo_field.Element).SqrtRatio(u, v)
	//if wasSquare == 0 {
	//	return nil, nil, errs.NewCoordinates("edwards25519: invalid point encoding")
	//}
	//yNeg := new(filippo_field.Element).Negate(y)
	//yy := new(filippo_field.Element).Select(yNeg, y, int(y.Bytes()[31]>>7))
	//
	//p1e, err := filippo.NewIdentityPoint().SetExtendedCoordinates(xc.V, yy, feOne, new(filippo_field.Element).Multiply(xc.V, yy))
	//if err != nil {
	//	return nil, nil, errs.WrapFailed(err, "couldnt set extended coordinates")
	//}
	//p1 = &Point{V: p1e}
	//
	//p2e, err := filippo.NewIdentityPoint().SetExtendedCoordinates(xc.V, yNeg, feOne, new(filippo_field.Element).Multiply(xc.V, new(filippo_field.Element).Negate(yy)))
	//if err != nil {
	//	return nil, nil, errs.WrapFailed(err, "couldnt set extended coordinates")
	//}
	//p2 = &Point{V: p2e}
	//
	//if p1.AffineY().IsEven() {
	//	return p1, p2, nil
	//} else {
	//	return p2, p1, nil
	//}
	panic("not implemented")
}
