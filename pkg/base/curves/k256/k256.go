package k256

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
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/arithmetic/limb4"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/hash2curve"
	k256impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/k256/impl"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256/impl/fp"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256/impl/fq"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

const Name = "secp256k1" // Compliant with Hash2curve (https://datatracker.ietf.org/doc/html/rfc9380)

var (
	k256Initonce sync.Once
	k256Instance Curve

	traceOfFrobenius, _ = new(saferith.Nat).SetHex(strings.ToUpper("14551231950b75fc4402da1722fc9baef"))
	jInvariant          = new(saferith.Nat).SetUint64(0)
)

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	hash2curve.CurveHasher

	_ ds.Incomparable
}

func k256Init() {
	k256Instance = Curve{}
	k256Instance.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&k256Instance),
		base.HASH2CURVE_APP_TAG,
		hash2curve.DstTagSswu,
	)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *Curve) SetHasherAppTag(appTag string) {
	c.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&k256Instance),
		appTag,
		hash2curve.DstTagSswu,
	)
}

func NewCurve() *Curve {
	k256Initonce.Do(k256Init)
	return &k256Instance
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
	return fq.New().Params.Modulus
}

func (c *Curve) Element() curves.Point {
	return c.AdditiveIdentity()
}

//func (c *Curve) OperateOver(operator algebra.Operator, ps ...curves.Point) (curves.Point, error) {
//	if operator != algebra.PointAddition {
//		return nil, errs.NewType("operator %v is not supported", operator)
//	}
//	current := c.AdditiveIdentity()
//	for _, p := range ps {
//		current = current.Operate(p)
//	}
//	return current, nil
//}.

func (c *Curve) Random(prng io.Reader) (curves.Point, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [base.WideFieldBytes]byte
	if _, err := io.ReadFull(prng, seed[:]); err != nil {
		return nil, errs.WrapRandomSample(err, "cannot read seed")
	}
	return c.Hash(seed[:])
}

func (c *Curve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (*Curve) HashWithDst(input []byte, dst []byte) (curves.Point, error) {
	p := k256impl.PointNew()
	u, err := NewCurve().HashToFieldElements(2, input, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to field element of K256 failed")
	}
	u0, ok0 := u[0].(*BaseFieldElement)
	u1, ok1 := u[1].(*BaseFieldElement)
	if !ok0 || !ok1 || u0.V == nil || u1.V == nil {
		return nil, errs.NewType("Cast to K256 field elements failed")
	}
	err = p.Arithmetic.Map(u0.V, u1.V, p)
	if err != nil {
		return nil, errs.WrapFailed(err, "Map to K256 point failed")
	}
	return &Point{V: p}, nil
}

func (c *Curve) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0p, ok0 := x0.(*Point)
	if !ok0 || x0p.V == nil {
		panic("x0 is not a non-empty K256 point")
	}
	x1p, ok1 := x1.(*Point)
	if !ok1 || x1p.V == nil {
		panic("x1 is not a non-empty K256 point")
	}
	p, okp := c.Element().(*Point)
	if !okp || p.V == nil {
		panic("curve.Element() not a non-empty K256 point")
	}
	p.V.X.CMove(x0p.V.X, x1p.V.X, choice)
	p.V.Y.CMove(x0p.V.Y, x1p.V.Y, choice)
	p.V.Z.CMove(x0p.V.Z, x1p.V.Z, choice)
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
	return &Point{
		V: k256impl.PointNew().Identity(),
	}
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
	return &Point{
		V: k256impl.PointNew().Generator(),
	}
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

func (*Curve) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
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
	value, err := k256impl.PointNew().SetNat(xx.Nat(), yy.Nat())
	if err != nil {
		return nil, errs.WrapCoordinates(err, "could not set x,y")
	}
	return &Point{V: value}, nil
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
		panic(errs.WrapFailed(err, "frobenius endomorphism did not succeed"))
	}
	return result
}

func (*Curve) TraceOfFrobenius() *saferith.Int {
	return new(saferith.Int).SetNat(traceOfFrobenius)
}

func (*Curve) JInvariant() *saferith.Int {
	return new(saferith.Int).SetNat(jInvariant)
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
			return nil, errs.NewFailed("invalid point type %s, expected PointK256", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = ptv.V
	}
	for i, sc := range scalars {
		s, ok := sc.(*Scalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarK256", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.V
	}
	value := k256impl.PointNew()
	_, err := value.SumOfProducts(nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}
	return &Point{V: value}, nil
}

func (*Curve) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*BaseFieldElement)
	if !ok {
		return nil, nil, errs.NewType("provided x coordinate is not a k256 field element")
	}
	rhs := fp.New()
	cPoint := new(Point)
	cPoint.V = k256impl.PointNew()
	cPoint.V.Arithmetic.RhsEq(rhs, xc.V)
	y, wasQr := fp.New().Sqrt(rhs)
	if !wasQr {
		return nil, nil, errs.NewCoordinates("x was not a quadratic residue")
	}
	p1e := k256impl.PointNew().Identity()
	p1e.X = xc.V
	p1e.Y = fp.New().Set(y)
	p1e.Z.SetOne()

	p2e := k256impl.PointNew().Identity()
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
