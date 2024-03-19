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
	bimpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

const NameG2 = "BLS12381G2" // Compliant with Hash2curve (https://datatracker.ietf.org/doc/html/rfc9380)

var (
	g2Initonce sync.Once
	g2Instance G2

	cofactorG2, _ = new(saferith.Nat).SetHex(strings.ToUpper("5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5"))
	g2FullOrder   = saferith.ModulusFromNat(new(saferith.Nat).Mul(r.Nat(), cofactorG2, r.Nat().AnnouncedLen()+cofactorG2.AnnouncedLen()))
)

var _ curves.Curve = (*G2)(nil)

type G2 struct {
	hash2curve.CurveHasher

	_ ds.Incomparable
}

func g2Init() {
	g2Instance = G2{}
	g2Instance.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&g2Instance),
		base.HASH2CURVE_APP_TAG,
		hash2curve.DstTagSswu,
	)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *G2) SetHasherAppTag(appTag string) {
	c.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&g2Instance),
		appTag,
		hash2curve.DstTagSswu,
	)
}

func NewG2() *G2 {
	g2Initonce.Do(g2Init)
	return &g2Instance
}

// === Basic Methods.

func (*G2) Name() string {
	return NameG2
}

func (*G2) Order() *saferith.Modulus {
	return g2FullOrder
}

func (c *G2) Element() curves.Point {
	return c.Identity()
}

func (c *G2) OperateOver(operator algebra.Operator, ps ...curves.Point) (curves.Point, error) {
	if operator != algebra.PointAddition {
		return nil, errs.NewType("operator %v is not supported", operator)
	}
	current := c.Identity()
	for _, p := range ps {
		current = current.Operate(p)
	}
	return current, nil
}

func (*G2) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.PointAddition}
}

func (*G2) Random(prng io.Reader) (curves.Point, error) {
	pt := new(bimpl.G2)
	u0, err := NewBaseFieldG2().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "couldn't generate random field element")
	}
	u1, err := NewBaseFieldG2().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "couldn't generate random field element")
	}
	u0fe, ok0 := u0.(*BaseFieldElementG2)
	u1fe, ok1 := u1.(*BaseFieldElementG2)
	if !ok0 || !ok1 {
		return nil, errs.WrapHashing(err, "Cast to BLS12381 G1 field elements failed")
	}
	pt.Map(u0fe.V, u1fe.V)
	return &PointG2{V: pt}, nil
}

func (c *G2) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (*G2) HashWithDst(input, dst []byte) (curves.Point, error) {
	pt := new(bimpl.G2)
	u, err := NewG2().HashToFieldElements(2, input, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to field element of BLS12381 G2 failed")
	}
	u0, ok0 := u[0].(*BaseFieldElementG2)
	u1, ok1 := u[1].(*BaseFieldElementG2)
	if !ok0 || !ok1 {
		return nil, errs.WrapHashing(err, "Cast to BLS12381 G2 field elements failed")
	}
	pt.Map(u0.V, u1.V)
	return &PointG2{V: pt}, nil
}

func (*G2) Select(choice int, x0, x1 curves.Point) curves.Point {
	x0pt, ok0 := x0.(*PointG2)
	x1pt, ok1 := x1.(*PointG2)
	if !ok0 || !ok1 {
		panic("Not a BLS12381 G1 point")
	}
	sPt := new(PointG2)
	sPt.V.CMove(x0pt.V, x1pt.V, choice)
	return sPt
}

// === Additive Groupoid Methods.

func (*G2) Add(x curves.Point, ys ...curves.Point) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Monoid Methods.

func (*G2) Identity() curves.Point {
	return &PointG2{
		V: new(bimpl.G2).Identity(),
	}
}

// === Additive Monoid Methods.

func (c *G2) AdditiveIdentity() curves.Point {
	return c.Identity()
}

// === Group Methods.

func (*G2) Cofactor() *saferith.Nat {
	return cofactorG2
}

// === Additive Group Methods.

func (*G2) Sub(x curves.Point, ys ...curves.Point) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Cyclic Group Methods.

func (*G2) Generator() curves.Point {
	return &PointG2{
		V: new(bimpl.G2).Generator(),
	}
}

// === Variety Methods.

func (*G2) Dimension() int {
	return 1
}

func (*G2) Discriminant() *saferith.Int {
	panic("not implemented")
}

// === Algebraic Curve Methods.

func (*G2) BaseField() curves.BaseField {
	return NewBaseFieldG2()
}

func (*G2) NewPoint(x, y curves.BaseFieldElement) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}

	xx, ok := x.(*BaseFieldElementG2)
	if !ok {
		return nil, errs.NewType("x is not of the right type")
	}
	yy, ok := y.(*BaseFieldElementG2)
	if !ok {
		return nil, errs.NewType("y is not of the right type")
	}
	v, err := new(bimpl.G2).SetComponents(
		(*[bimpl.FieldBytesFp2]byte)(xx.Bytes()),
		(*[bimpl.FieldBytesFp2]byte)(yy.Bytes()),
	)
	if err != nil {
		return nil, errs.WrapCoordinates(err, "couldn't set coordinates")
	}
	return &PointG2{V: v}, nil
}

// === Elliptic Curve Methods.

func (c *G2) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (*G2) ScalarField() curves.ScalarField {
	return NewScalarFieldG2()
}

func (c *G2) Point() curves.Point {
	return c.Element()
}

func (c *G2) Scalar() curves.Scalar {
	return c.ScalarField().Element()
}

func (c *G2) BaseFieldElement() curves.BaseFieldElement {
	return c.BaseField().Zero()
}

func (c *G2) FrobeniusEndomorphism(p curves.Point) curves.Point {
	pp, ok := p.(*PointG2)
	if !ok {
		panic("given point is not of the right type")
	}
	x := pp.AffineX()
	y := pp.AffineY()
	characteristic := NewBaseFieldElementG2(0).SetNat(NewBaseFieldG2().Characteristic())
	result, err := c.NewPoint(x.Exp(characteristic), y.Exp(characteristic))
	if err != nil {
		panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	}
	return result
}

func (*G2) TraceOfFrobenius() *saferith.Int {
	// TODO: find number of rational points
	panic("not implemented.")
}

func (*G2) JInvariant() *saferith.Int {
	return new(saferith.Int).SetUint64(0)
}

// === Prime SubGroup Methods.

func (*G2) SubGroupOrder() *saferith.Modulus {
	return r
}

func (c *G2) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (*G2) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]*bimpl.G2, len(points))
	nScalars := make([]*impl.FieldValue, len(scalars))
	for i, pt := range points {
		pp, ok := pt.(*PointG2)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointBls12381G2", reflect.TypeOf(pt).Name())
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
	value, err := new(bimpl.G2).SumOfProducts(nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}
	return &PointG2{V: value}, nil
}

func (*G2) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	panic("not implemented")
}
