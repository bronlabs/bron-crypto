package p256

import (
	"io"
	"reflect"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb4"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	p256impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fq"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

const Name = "P256" // Compliant with Hash2curve (https://datatracker.ietf.org/doc/html/rfc9380)

var (
	p256Initonce sync.Once
	p256Instance Curve
)

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	hash2curve.CurveHasher

	_ ds.Incomparable
}

func p256Init() {
	p256Instance = Curve{}
	p256Instance.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&p256Instance),
		base.HASH2CURVE_APP_TAG,
		hash2curve.DstTagSswu,
	)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *Curve) SetHasherAppTag(appTag string) {
	c.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&p256Instance),
		appTag,
		hash2curve.DstTagSswu,
	)
}

func NewCurve() *Curve {
	p256Initonce.Do(p256Init)
	return &p256Instance
}

func (*Curve) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Contains(e curves.Point) bool {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Iter() <-chan curves.Point {
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

func (c *Curve) Random(prng io.Reader) (curves.Point, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [64]byte
	if _, err := io.ReadFull(prng, seed[:]); err != nil {
		return nil, errs.WrapRandomSample(err, "could not read seed")
	}
	return c.Hash(seed[:])
}

func (c *Curve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (*Curve) HashWithDst(input, dst []byte) (curves.Point, error) {
	p := p256impl.PointNew()
	u, err := NewCurve().HashToFieldElements(2, input, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to field element of P256 failed")
	}
	u0, ok0 := u[0].(*BaseFieldElement)
	u1, ok1 := u[1].(*BaseFieldElement)
	if !ok0 || !ok1 {
		return nil, errs.NewType("cast to P256 field element failed")
	}
	err = p.Arithmetic.Map(u0.V, u1.V, p)
	if err != nil {
		return nil, errs.WrapHashing(err, "map to P256 point failed")
	}
	return &Point{V: p}, nil
}

func (c *Curve) Select(choice bool, x0, x1 curves.Point) curves.Point {
	x0p, ok0 := x0.(*Point)
	x1p, ok1 := x1.(*Point)
	p, okp := c.Element().(*Point)
	if !ok0 || !ok1 || okp {
		panic("Not a K256 point")
	}
	p.V.X.CMove(x0p.V.X, x1p.V.X, utils.BoolTo[int](choice))
	p.V.Y.CMove(x0p.V.Y, x1p.V.Y, utils.BoolTo[int](choice))
	p.V.Z.CMove(x0p.V.Z, x1p.V.Z, utils.BoolTo[int](choice))
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
	return &Point{
		V: p256impl.PointNew().Identity(),
	}
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
	return &Point{
		V: p256impl.PointNew().Generator(),
	}
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
	value, err := p256impl.PointNew().SetNat(xx.Nat(), yy.Nat())
	if err != nil {
		return nil, errs.WrapCoordinates(err, "could not set x,y")
	}
	return &Point{V: value}, nil
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

func (c *Curve) FrobeniusEndomorphism(p curves.Point) curves.Point {
	pp, ok := p.(*Point)
	if !ok {
		panic("given point is not of the right type")
	}
	x := pp.AffineX()
	y := pp.AffineY()
	characteristic := NewBaseFieldElement(0).SetNat(NewBaseField().Characteristic())
	result, err := c.NewPoint(x.Exp(characteristic.Nat()), y.Exp(characteristic.Nat()))
	if err != nil {
		panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	}
	return result
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
	return fq.New().Params.Modulus
}

func (c *Curve) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]*limb4.EllipticPoint, len(points))
	nScalars := make([]*limb4.FieldValue, len(scalars))
	for i, pt := range points {
		ptv, ok := pt.(*Point)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointP256", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = ptv.V
	}
	for i, sc := range scalars {
		s, ok := sc.(*Scalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarP256", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.V
	}
	value := p256impl.PointNew()
	_, err := value.SumOfProducts(nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}
	return &Point{V: value}, nil
}

func (c *Curve) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*BaseFieldElement)
	if !ok {
		return nil, nil, errs.NewType("provided x coordinate is not a p256 field element")
	}
	rhs := fp.New()
	cp, ok := c.Point().(*Point)
	if !ok {
		return nil, nil, errs.NewType("provided point is not a p256 point")
	}
	cp.V.Arithmetic.RhsEq(rhs, xc.V)
	y, wasQr := fp.New().Sqrt(rhs)
	if !wasQr {
		return nil, nil, errs.NewCoordinates("x was not a quadratic residue")
	}
	p1e := p256impl.PointNew().Identity()
	p1e.X = xc.V
	p1e.Y = fp.New().Set(y)
	p1e.Z.SetOne()

	p2e := p256impl.PointNew().Identity()
	p2e.X = xc.V
	p2e.Y = fp.New().Neg(fp.New().Set(y))
	p2e.Z.SetOne()

	p1 := &Point{V: p1e}
	p2 := &Point{V: p2e}

	if p1.AffineY().IsEven() {
		return p1, p2, nil
	}
	return p2, p1, nil
}
