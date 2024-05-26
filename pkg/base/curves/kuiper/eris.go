package kuiper

import (
	"io"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

const NameEris = "Eris"

var (
	erisInitOnce sync.Once
	erisInstance Eris
)

var _ curves.Curve = (*Eris)(nil)

type Eris struct {
	hash2curve.CurveHasher

	_ ds.Incomparable
}

func erisInit() {
	erisInstance = Eris{}
	//plutoInstance.CurveHasher = hash2curve.NewCurveHasherSha256(
	//	curves.Curve(&plutoInstance),
	//	base.HASH2CURVE_APP_TAG,
	//	hash2curve.DstTagSswu,
	//)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (*Eris) SetHasherAppTag(appTag string) {
	//c.CurveHasher = hash2curve.NewCurveHasherSha256(
	//	curves.Curve(&plutoInstance),
	//	appTag,
	//	hash2curve.DstTagSswu,
	//)
	// TODO: not implemented
}

func NewEris() *Eris {
	erisInitOnce.Do(erisInit)
	return &erisInstance
}

// === Basic Methods.

func (*Eris) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*Eris) Contains(e curves.Point) bool {
	//TODO implement me
	panic("implement me")
}

func (*Eris) Iterator() ds.Iterator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*Eris) Operators() []algebra.BinaryOperator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (c *Eris) Unwrap() curves.Curve {
	return c
}

func (*Eris) IsDefinedUnder(operator algebra.BinaryOperator[curves.Point]) bool {
	//TODO implement me
	panic("implement me")
}

func (*Eris) Op(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], ys ...algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Eris) Addition() algebra.Addition[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*Eris) ModuleScalarRing() algebra.ModuleBaseRing[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*Eris) AlgebraicVarietyBaseField() algebra.AlgebraicVarietyBaseField[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*Eris) VectorSpaceScalarField() algebra.VectorSpaceBaseField[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (c *Eris) BasePoint() curves.Point {
	return c.Generator()
}

func (*Eris) DLog(b, x algebra.CyclicGroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (*Eris) ElementSize() int {
	panic("implement me")
}

func (*Eris) WideElementSize() int {
	panic("implement me")
}

func (*Eris) SuperGroupOrder() *saferith.Modulus {
	return impl.FqModulus
}

func (*Eris) Name() string {
	return NameEris
}

func (*Eris) Order() *saferith.Modulus {
	return impl.FqModulus
}

func (c *Eris) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*Eris) Random(prng io.Reader) (curves.Point, error) {
	panic("not implemented")
	//if prng == nil {
	//	return nil, errs.NewIsNil("prng is nil")
	//}
	//pt := new(impl.PlutoPoint)
	//u0, err := NewPlutoBaseField().Random(prng)
	//if err != nil {
	//	return nil, errs.WrapRandomSample(err, "couldn't generate random field element")
	//}
	//u1, err := NewPlutoBaseField().Random(prng)
	//if err != nil {
	//	return nil, errs.WrapRandomSample(err, "couldn't generate random field element")
	//}
	//u0fe, ok0 := u0.(*PlutoBaseFieldElement)
	//u1fe, ok1 := u1.(*PlutoBaseFieldElement)
	//if !ok0 || !ok1 {
	//	return nil, errs.WrapType(err, "Cast to BLS12381 G1 field elements failed")
	//}
	//pt.Map(u0fe.V, u1fe.V)
	//return &PlutoPoint{V: pt}, nil
}

func (c *Eris) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (*Eris) HashWithDst(input, dst []byte) (curves.Point, error) {
	panic("not implemented")
	//pt := new(bls12381impl.G1)
	//u, err := NewPluto().HashToFieldElements(2, input, dst)
	//if err != nil {
	//	return nil, errs.WrapHashing(err, "hash to field element of BLS12381 G1 failed")
	//}
	//u0, ok0 := u[0].(*BaseFieldElementG1)
	//u1, ok1 := u[1].(*BaseFieldElementG1)
	//if !ok0 || !ok1 {
	//	return nil, errs.WrapType(err, "Cast to BLS12381 G1 field elements failed")
	//}
	//pt.Map(u0.V, u1.V)
	//return &PlutoPoint{V: pt}, nil
}

func (*Eris) Select(choice bool, x0, x1 curves.Point) curves.Point {
	x0pt, ok0 := x0.(*ErisPoint)
	x1pt, ok1 := x1.(*ErisPoint)
	if !ok0 || !ok1 {
		panic("Not a Pluto point")
	}
	sPt := new(ErisPoint)
	sPt.V.CMove(&x0pt.V, &x1pt.V, utils.BoolTo[uint64](choice))
	return sPt
}

// === Additive Groupoid Methods.

func (*Eris) Add(x algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Monoid Methods.

func (*Eris) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (*Eris) AdditiveIdentity() curves.Point {
	return &ErisPoint{
		V: *new(impl.ErisPoint).Identity(),
	}
}

// === Group Methods.

func (*Eris) CoFactor() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1).Resize(1)
}

// === Additive Group Methods.

func (*Eris) Sub(x algebra.AdditiveGroupElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Cyclic Group Methods.

func (*Eris) Generator() curves.Point {
	return &ErisPoint{
		V: *new(impl.ErisPoint).Generator(),
	}
}

// === Variety Methods.

func (*Eris) Dimension() int {
	return 1
}

func (*Eris) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("1b00"))
	return new(saferith.Int).SetNat(result).Neg(1)
}

// === Algebraic Curve Methods.

func (*Eris) BaseField() curves.BaseField {
	return NewErisBaseField()
}

func (*Eris) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}
	xx, ok := x.(*ErisBaseFieldElement)
	if !ok {
		return nil, errs.NewType("x is not of the right type")
	}
	yy, ok := y.(*ErisBaseFieldElement)
	if !ok {
		return nil, errs.NewType("y is not of the right type")
	}

	value := new(impl.ErisPoint)
	value.X.Set(&xx.V)
	value.Y.Set(&yy.V)
	value.Z.SetOne()
	return &ErisPoint{V: *value}, nil
}

// === Elliptic Curve Methods.

func (c *Eris) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (*Eris) ScalarField() curves.ScalarField {
	return NewErisScalarField()
}

func (c *Eris) Point() curves.Point {
	return c.Element()
}

func (c *Eris) Scalar() curves.Scalar {
	return c.ScalarField().Element()
}

func (c *Eris) BaseFieldElement() curves.BaseFieldElement {
	return c.BaseField().Zero()
}

func (c *Eris) FrobeniusEndomorphism(p curves.Point) curves.Point {
	pp, ok := p.(*ErisPoint)
	if !ok {
		panic("given point is not of the right type")
	}
	x := pp.AffineX()
	y := pp.AffineY()
	characteristic := NewErisBaseField().Characteristic()
	result, err := c.NewPoint(x.Exp(characteristic), y.Exp(characteristic))
	if err != nil {
		panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	}
	return result
}

func (*Eris) TraceOfFrobenius() *saferith.Int {
	// TODO: find number of rational points
	panic("not implemented.")
}

func (*Eris) JInvariant() *saferith.Int {
	return new(saferith.Int).SetUint64(0)
}

// === Prime SubGroup Methods.

func (*Eris) SubGroupOrder() *saferith.Modulus {
	return impl.FqModulus
}

func (c *Eris) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*Eris) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	panic("not implemented")
	//nPoints := make([]*impl.PlutoPoint, len(points))
	//nScalars := make([]*impl.Fq, len(scalars))
	//for i, pt := range points {
	//	pp, ok := pt.(*PlutoPoint)
	//	if !ok {
	//		return nil, errs.NewFailed("invalid point type %s, expected PointBls12381G1", reflect.TypeOf(pt).Name())
	//	}
	//	nPoints[i] = &pp.V
	//}
	//for i, sc := range scalars {
	//	s, ok := sc.(*PlutoTritonScalar)
	//	if !ok {
	//		return nil, errs.NewFailed("invalid scalar type %s, expected ScalarBls12381", reflect.TypeOf(sc).Name())
	//	}
	//	nScalars[i] = &s.V
	//}
	//value, err := new(impl.PlutoPoint).SumOfProducts(nPoints, nScalars)
	//if err != nil {
	//	return nil, errs.WrapFailed(err, "multi scalar multiplication failed")
	//}
	//return &PlutoPoint{V: value}, nil
}

func (*Eris) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	panic("not implemented")
}
