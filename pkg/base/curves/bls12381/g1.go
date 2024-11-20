package bls12381

import (
	"io"
	"iter"
	"reflect"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb4"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

const NameG1 = "BLS12381G1" // Compliant with Hash2curve (https://datatracker.ietf.org/doc/html/rfc9380)

var (
	g1Initonce sync.Once
	g1Instance G1

	cofactorG1, _ = new(saferith.Nat).SetHex(strings.ToUpper("396C8C005555E1568C00AAAB0000AAAB"))
	g1FullOrder   = saferith.ModulusFromNat(new(saferith.Nat).Mul(r.Nat(), cofactorG1, r.Nat().AnnouncedLen()+cofactorG1.AnnouncedLen()))
)

var _ curves.Curve = (*G1)(nil)

type G1 struct {
	hash2curve.CurveHasher

	_ ds.Incomparable
}

func g1Init() {
	g1Instance = G1{}
	g1Instance.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&g1Instance),
		base.HASH2CURVE_APP_TAG,
		hash2curve.DstTagSswu,
	)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *G1) SetHasherAppTag(appTag string) {
	c.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&g1Instance),
		appTag,
		hash2curve.DstTagSswu,
	)
}

func NewG1() *G1 {
	g1Initonce.Do(g1Init)
	return &g1Instance
}

// === Basic Methods.

func (*G1) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*G1) Contains(e curves.Point) bool {
	//TODO implement me
	panic("implement me")
}

func (*G1) Iter() iter.Seq[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*G1) Operators() []algebra.BinaryOperator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (c *G1) Unwrap() curves.Curve {
	return c
}

func (*G1) IsDefinedUnder(operator algebra.BinaryOperator[curves.Point]) bool {
	//TODO implement me
	panic("implement me")
}

func (*G1) Op(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], ys ...algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*G1) Addition() algebra.Addition[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*G1) ModuleScalarRing() algebra.ModuleBaseRing[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*G1) AlgebraicVarietyBaseField() algebra.AlgebraicVarietyBaseField[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*G1) VectorSpaceScalarField() algebra.VectorSpaceBaseField[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (c *G1) BasePoint() curves.Point {
	return c.Generator()
}

func (*G1) DLog(b, x algebra.CyclicGroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (*G1) ElementSize() int {
	panic("implement me")
}

func (*G1) WideElementSize() int {
	panic("implement me")
}

func (*G1) SuperGroupOrder() *saferith.Modulus {
	return g1FullOrder
}

func (*G1) Name() string {
	return NameG1
}

func (*G1) Order() *saferith.Modulus {
	return r
}

func (c *G1) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*G1) Random(prng io.Reader) (curves.Point, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	pt := new(bls12381impl.G1)
	u0, err := NewBaseFieldG1().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "couldn't generate random field element")
	}
	u1, err := NewBaseFieldG1().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "couldn't generate random field element")
	}
	u0fe, ok0 := u0.(*BaseFieldElementG1)
	u1fe, ok1 := u1.(*BaseFieldElementG1)
	if !ok0 || !ok1 || u0fe.V == nil || u1fe.V == nil {
		return nil, errs.WrapType(err, "Cast to BLS12381 G1 field elements failed")
	}
	pt.Map(u0fe.V, u1fe.V)
	return &PointG1{V: pt}, nil
}

func (c *G1) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (*G1) HashWithDst(input, dst []byte) (curves.Point, error) {
	pt := new(bls12381impl.G1)
	u, err := NewG1().HashToFieldElements(2, input, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to field element of BLS12381 G1 failed")
	}
	u0, ok0 := u[0].(*BaseFieldElementG1)
	u1, ok1 := u[1].(*BaseFieldElementG1)
	if !ok0 || !ok1 || u0.V == nil || u1.V == nil {
		return nil, errs.WrapType(err, "Cast to BLS12381 G1 field elements failed")
	}
	pt.Map(u0.V, u1.V)
	return &PointG1{V: pt}, nil
}

func (*G1) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0pt, ok0 := x0.(*PointG1)
	if !ok0 || x0pt.V == nil {
		panic("x0 is not a non-empty BLS12381 G1 element")
	}
	x1pt, ok1 := x1.(*PointG1)
	if !ok1 || x1pt.V == nil {
		panic("x1 is ot a non-empty BLS12381 G1 element")
	}
	sPt := new(PointG1)
	sPt.V.CMove(x0pt.V, x1pt.V, choice)
	return sPt
}

// === Additive Groupoid Methods.

func (*G1) Add(x algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Monoid Methods.

func (*G1) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (*G1) AdditiveIdentity() curves.Point {
	return &PointG1{
		V: new(bls12381impl.G1).Identity(),
	}
}

// === Group Methods.

func (*G1) CoFactor() *saferith.Nat {
	return cofactorG1
}

// === Additive Group Methods.

func (*G1) Sub(x algebra.AdditiveGroupElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Cyclic Group Methods.

func (*G1) Generator() curves.Point {
	return &PointG1{
		V: new(bls12381impl.G1).Generator(),
	}
}

// === Variety Methods.

func (*G1) Dimension() int {
	return 1
}

func (*G1) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("1b00"))
	return new(saferith.Int).SetNat(result).Neg(1)
}

// === Algebraic Curve Methods.

func (*G1) BaseField() curves.BaseField {
	return NewBaseFieldG1()
}

func (*G1) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}
	xx, ok := x.(*BaseFieldElementG1)
	if !ok {
		return nil, errs.NewType("x is not of the right type")
	}
	yy, ok := y.(*BaseFieldElementG1)
	if !ok {
		return nil, errs.NewType("y is not of the right type")
	}

	value, err := new(bls12381impl.G1).SetNat(xx.Nat(), yy.Nat())
	if err != nil {
		return nil, errs.WrapCoordinates(err, "invalid coordinates")
	}
	return &PointG1{V: value}, nil
}

// === Elliptic Curve Methods.

func (c *G1) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (*G1) ScalarField() curves.ScalarField {
	return NewScalarFieldG1()
}

func (c *G1) Point() curves.Point {
	return c.Element()
}

func (c *G1) Scalar() curves.Scalar {
	return c.ScalarField().Element()
}

func (c *G1) BaseFieldElement() curves.BaseFieldElement {
	return c.BaseField().Zero()
}

func (c *G1) FrobeniusEndomorphism(p curves.Point) curves.Point {
	pp, ok := p.(*PointG1)
	if !ok {
		panic("given point is not of the right type")
	}
	x := pp.AffineX()
	y := pp.AffineY()
	characteristic := NewBaseFieldG1().Characteristic()
	result, err := c.NewPoint(x.Exp(characteristic), y.Exp(characteristic))
	if err != nil {
		panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	}
	return result
}

func (*G1) TraceOfFrobenius() *saferith.Int {
	// TODO: find number of rational points
	panic("not implemented.")
}

func (*G1) JInvariant() *saferith.Int {
	return new(saferith.Int).SetUint64(0)
}

// === Prime SubGroup Methods.

func (*G1) SubGroupOrder() *saferith.Modulus {
	return r
}

func (c *G1) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*G1) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]*bls12381impl.G1, len(points))
	nScalars := make([]*limb4.FieldValue, len(scalars))
	for i, pt := range points {
		pp, ok := pt.(*PointG1)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointBls12381G1", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = pp.V
	}
	for i, sc := range scalars {
		s, ok := sc.(*Scalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarBls12381", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.V
	}
	value, err := new(bls12381impl.G1).SumOfProducts(nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multi scalar multiplication failed")
	}
	return &PointG1{V: value}, nil
}

func (*G1) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	panic("not implemented")
}
