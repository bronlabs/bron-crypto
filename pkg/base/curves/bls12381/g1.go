package bls12381

import (
	"io"
	"reflect"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
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

	_ types.Incomparable
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

func (*G1) Name() string {
	return NameG1
}

func (*G1) Order() *saferith.Modulus {
	return g1FullOrder
}

func (c *G1) Element() curves.Point {
	return c.Identity()
}

func (c *G1) OperateOver(operator algebra.Operator, ps ...curves.Point) (curves.Point, error) {
	if operator != algebra.PointAddition {
		return nil, errs.NewInvalidType("operator %v is not supported", operator)
	}
	current := c.Identity()
	for _, p := range ps {
		current = current.Operate(p)
	}
	return current, nil
}

func (*G1) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.PointAddition}
}

func (*G1) Random(prng io.Reader) (curves.Point, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	pt := new(bls12381impl.G1)
	u0, err := NewBaseFieldG1().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "couldn't generate random field element")
	}
	u1, err := NewBaseFieldG1().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "couldn't generate random field element")
	}
	u0fe, ok0 := u0.(*BaseFieldElementG1)
	u1fe, ok1 := u1.(*BaseFieldElementG1)
	if !ok0 || !ok1 {
		return nil, errs.WrapHashingFailed(err, "Cast to BLS12381 G1 field elements failed")
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
		return nil, errs.WrapHashingFailed(err, "hash to field element of BLS12381 G1 failed")
	}
	u0, ok0 := u[0].(*BaseFieldElementG1)
	u1, ok1 := u[1].(*BaseFieldElementG1)
	if !ok0 || !ok1 {
		return nil, errs.WrapHashingFailed(err, "Cast to BLS12381 G1 field elements failed")
	}
	pt.Map(u0.V, u1.V)
	return &PointG1{V: pt}, nil
}

// === Additive Groupoid Methods.

func (*G1) Add(x curves.Point, ys ...curves.Point) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Monoid Methods.

func (*G1) Identity() curves.Point {
	return &PointG1{
		V: new(bls12381impl.G1).Identity(),
	}
}

// === Additive Monoid Methods.

func (c *G1) AdditiveIdentity() curves.Point {
	return c.Identity()
}

// === Group Methods.

func (*G1) Cofactor() *saferith.Nat {
	return cofactorG1
}

// === Additive Group Methods.

func (*G1) Sub(x curves.Point, ys ...curves.Point) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
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

func (*G1) NewPoint(x, y curves.BaseFieldElement) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}
	xx, ok := x.(*BaseFieldElementG1)
	if !ok {
		return nil, errs.NewInvalidType("x is not of the right type")
	}
	yy, ok := y.(*BaseFieldElementG1)
	if !ok {
		return nil, errs.NewInvalidType("y is not of the right type")
	}

	value, err := new(bls12381impl.G1).SetNat(xx.Nat(), yy.Nat())
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "invalid coordinates")
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
	characteristic := NewBaseFieldElementG1(0).SetNat(NewBaseFieldG1().Characteristic())
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

func (c *G1) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (*G1) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]*bls12381impl.G1, len(points))
	nScalars := make([]*impl.FieldValue, len(scalars))
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
