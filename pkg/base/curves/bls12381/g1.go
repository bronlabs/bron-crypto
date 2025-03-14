package bls12381

import (
	"io"
	"iter"
	"reflect"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

const (
	NameG1                  = "BLS12381G1"
	Hash2CurveSuiteG1       = "BLS12381G1_XMD:SHA-256_SSWU_RO_"
	Hash2CurveScalarSuiteG1 = "BLS12381G1_XMD:SHA-256_SSWU_RO_SC_"
)

var (
	g1InitOnce sync.Once
	g1Instance G1

	g1Cofactor, _      = new(saferith.Nat).SetHex(strings.ToUpper("396c8c005555e1568c00aaab0000aaab"))
	g1HEffective, _    = new(saferith.Nat).SetHex(strings.ToUpper("d201000000010001"))
	g1SubGroupOrder, _ = saferith.ModulusFromHex(strings.ToUpper("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"))
	g1Order            = saferith.ModulusFromNat(new(saferith.Nat).Mul(g1Cofactor, g1SubGroupOrder.Nat(), -1))
)

var _ curves.Curve = (*G1)(nil)

type G1 struct {
	_ ds.Incomparable
}

func g1Init() {
	g1Instance = G1{}
}

func NewG1() *G1 {
	g1InitOnce.Do(g1Init)
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
	return g1Order
}

func (*G1) Name() string {
	return NameG1
}

func (*G1) Order() *saferith.Modulus {
	return bls12381SubGroupOrder
}

func (c *G1) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*G1) Random(prng io.Reader) (curves.Point, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	pt := new(PointG1)
	ok := pt.V.SetRandom(prng)
	if ok != 1 {
		return nil, errs.NewRandomSample("bls12381 g1")
	}

	return pt, nil
}

func (*G1) HashToFieldElements(count int, dstPrefix string, msg []byte) (u []curves.BaseFieldElement, err error) {
	out := make([]bls12381Impl.Fp, count)
	h2c.HashToField(out[:], bls12381Impl.G1CurveHasherParams{}, dstPrefix+Hash2CurveSuiteG1, msg)

	u = make([]curves.BaseFieldElement, count)
	for i := range out {
		v := new(BaseFieldElementG1)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (c *G1) HashToScalars(count int, dstPrefix string, msg []byte) (u []curves.Scalar, err error) {
	out := make([]bls12381Impl.Fq, count)
	h2c.HashToField(out[:], bls12381Impl.G1CurveHasherParams{}, dstPrefix+Hash2CurveScalarSuiteG1, msg)

	u = make([]curves.Scalar, count)
	for i := range out {
		s := &Scalar{G: c}
		s.V.Set(&out[i])
		u[i] = s
	}

	return u, nil
}

func (c *G1) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuiteG1, input)
}

func (*G1) HashWithDst(dst string, input []byte) (curves.Point, error) {
	result := new(PointG1)
	result.V.Hash(dst, input)
	return result, nil
}

func (*G1) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0pt, ok0 := x0.(*PointG1)
	if !ok0 {
		panic("x0 is not a non-empty BLS12381 G1 element")
	}
	x1pt, ok1 := x1.(*PointG1)
	if !ok1 {
		panic("x1 is ot a non-empty BLS12381 G1 element")
	}
	sPt := new(PointG1)
	sPt.V.Select(choice, &x0pt.V, &x1pt.V)
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
	result := new(PointG1)
	result.V.SetIdentity()
	return result
}

// === Group Methods.

func (*G1) CoFactor() *saferith.Nat {
	return g1Cofactor
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
	result := new(PointG1)
	result.V.SetGenerator()
	return result
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

func (c *G1) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
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

	if xx.IsAdditiveIdentity() && yy.IsAdditiveIdentity() {
		return c.AdditiveIdentity(), nil
	}

	result := new(PointG1)
	ok2 := result.V.SetAffine(&xx.V, &yy.V)
	if ok2 != 1 {
		return nil, errs.NewFailed("invalid coordinates")
	}

	return result, nil
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

func (*G1) FrobeniusEndomorphism(p curves.Point) curves.Point {
	//pp, ok := p.(*PointG1)
	//if !ok {
	//	panic("given point is not of the right type")
	//}
	//x := pp.AffineX()
	//y := pp.AffineY()
	//characteristic := NewBaseFieldG1().Characteristic()
	//result, err := c.NewPoint(x.Exp(characteristic), y.Exp(characteristic))
	//if err != nil {
	//	panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	//}
	//return result
	panic("implement me")
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
	return bls12381SubGroupOrder
}

func (c *G1) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*G1) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]bls12381Impl.G1Point, len(points))
	nScalars := make([][]byte, len(scalars))
	for i, pt := range points {
		pp, ok := pt.(*PointG1)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointBls12381G1", reflect.TypeOf(pt).Name())
		}
		nPoints[i].Set(&pp.V)
	}
	for i, sc := range scalars {
		s, ok := sc.(*Scalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarBls12381", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.V.Bytes()
	}

	value := new(PointG1)
	err := pointsImpl.MultiScalarMul[*bls12381Impl.Fp](&value.V, nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multi scalar")
	}
	return value, nil
}

func (*G1) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	panic("not implemented")
}
