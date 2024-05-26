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

const NamePluto = "Pluto"

var (
	plutoInitOnce sync.Once
	plutoInstance Pluto
)

var _ curves.Curve = (*Pluto)(nil)

type Pluto struct {
	hash2curve.CurveHasher

	_ ds.Incomparable
}

func plutoInit() {
	plutoInstance = Pluto{}
	//plutoInstance.CurveHasher = hash2curve.NewCurveHasherSha256(
	//	curves.Curve(&plutoInstance),
	//	base.HASH2CURVE_APP_TAG,
	//	hash2curve.DstTagSswu,
	//)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (*Pluto) SetHasherAppTag(appTag string) {
	//c.CurveHasher = hash2curve.NewCurveHasherSha256(
	//	curves.Curve(&plutoInstance),
	//	appTag,
	//	hash2curve.DstTagSswu,
	//)
	// TODO: not implemented
}

func NewPluto() *Pluto {
	plutoInitOnce.Do(plutoInit)
	return &plutoInstance
}

// === Basic Methods.

func (*Pluto) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*Pluto) Contains(e curves.Point) bool {
	//TODO implement me
	panic("implement me")
}

func (*Pluto) Iterator() ds.Iterator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*Pluto) Operators() []algebra.BinaryOperator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (c *Pluto) Unwrap() curves.Curve {
	return c
}

func (*Pluto) IsDefinedUnder(operator algebra.BinaryOperator[curves.Point]) bool {
	//TODO implement me
	panic("implement me")
}

func (*Pluto) Op(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], ys ...algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Pluto) Addition() algebra.Addition[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*Pluto) ModuleScalarRing() algebra.ModuleBaseRing[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*Pluto) AlgebraicVarietyBaseField() algebra.AlgebraicVarietyBaseField[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*Pluto) VectorSpaceScalarField() algebra.VectorSpaceBaseField[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (c *Pluto) BasePoint() curves.Point {
	return c.Generator()
}

func (*Pluto) DLog(b, x algebra.CyclicGroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (*Pluto) ElementSize() int {
	panic("implement me")
}

func (*Pluto) WideElementSize() int {
	panic("implement me")
}

func (*Pluto) SuperGroupOrder() *saferith.Modulus {
	return impl.FqModulus
}

func (*Pluto) Name() string {
	return NamePluto
}

func (*Pluto) Order() *saferith.Modulus {
	return impl.FqModulus
}

func (c *Pluto) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*Pluto) Random(prng io.Reader) (curves.Point, error) {
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

func (c *Pluto) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (*Pluto) HashWithDst(input, dst []byte) (curves.Point, error) {
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

func (*Pluto) Select(choice bool, x0, x1 curves.Point) curves.Point {
	x0pt, ok0 := x0.(*PlutoPoint)
	x1pt, ok1 := x1.(*PlutoPoint)
	if !ok0 || !ok1 {
		panic("Not a Pluto point")
	}
	sPt := new(PlutoPoint)
	sPt.V.CMove(&x0pt.V, &x1pt.V, utils.BoolTo[uint64](choice))
	return sPt
}

// === Additive Groupoid Methods.

func (*Pluto) Add(x algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Monoid Methods.

func (*Pluto) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (*Pluto) AdditiveIdentity() curves.Point {
	return &PlutoPoint{
		V: *new(impl.PlutoPoint).Identity(),
	}
}

// === Group Methods.

func (*Pluto) CoFactor() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1).Resize(1)
}

// === Additive Group Methods.

func (*Pluto) Sub(x algebra.AdditiveGroupElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Cyclic Group Methods.

func (*Pluto) Generator() curves.Point {
	return &PlutoPoint{
		V: *new(impl.PlutoPoint).Generator(),
	}
}

// === Variety Methods.

func (*Pluto) Dimension() int {
	return 1
}

func (*Pluto) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("1b00"))
	return new(saferith.Int).SetNat(result).Neg(1)
}

// === Algebraic Curve Methods.

func (*Pluto) BaseField() curves.BaseField {
	return NewPlutoBaseField()
}

func (*Pluto) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}
	xx, ok := x.(*PlutoBaseFieldElement)
	if !ok {
		return nil, errs.NewType("x is not of the right type")
	}
	yy, ok := y.(*PlutoBaseFieldElement)
	if !ok {
		return nil, errs.NewType("y is not of the right type")
	}

	value := new(impl.PlutoPoint)
	value.X.Set(&xx.V)
	value.Y.Set(&yy.V)
	value.Z.SetOne()
	return &PlutoPoint{V: *value}, nil
}

// === Elliptic Curve Methods.

func (c *Pluto) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (*Pluto) ScalarField() curves.ScalarField {
	return NewPlutoScalarField()
}

func (c *Pluto) Point() curves.Point {
	return c.Element()
}

func (c *Pluto) Scalar() curves.Scalar {
	return c.ScalarField().Element()
}

func (c *Pluto) BaseFieldElement() curves.BaseFieldElement {
	return c.BaseField().Zero()
}

func (c *Pluto) FrobeniusEndomorphism(p curves.Point) curves.Point {
	pp, ok := p.(*PlutoPoint)
	if !ok {
		panic("given point is not of the right type")
	}
	x := pp.AffineX()
	y := pp.AffineY()
	characteristic := NewPlutoBaseField().Characteristic()
	result, err := c.NewPoint(x.Exp(characteristic), y.Exp(characteristic))
	if err != nil {
		panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	}
	return result
}

func (*Pluto) TraceOfFrobenius() *saferith.Int {
	// TODO: find number of rational points
	panic("not implemented.")
}

func (*Pluto) JInvariant() *saferith.Int {
	return new(saferith.Int).SetUint64(0)
}

// === Prime SubGroup Methods.

func (*Pluto) SubGroupOrder() *saferith.Modulus {
	return impl.FqModulus
}

func (c *Pluto) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*Pluto) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
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

func (*Pluto) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	panic("not implemented")
}
