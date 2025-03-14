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
	NameG2                  = "BLS12381G2"
	Hash2CurveSuiteG2       = "BLS12381G2_XMD:SHA-256_SSWU_RO_"
	Hash2CurveScalarSuiteG2 = "BLS12381G2_XMD:SHA-256_SSWU_RO_SC_"
)

var (
	g2InitOnce sync.Once
	g2Instance G2

	g2Cofactor, _      = new(saferith.Nat).SetHex(strings.ToUpper("5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5"))
	g2HEffective, _    = new(saferith.Nat).SetHex(strings.ToUpper("bc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551"))
	g2SubGroupOrder, _ = saferith.ModulusFromHex(strings.ToUpper("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"))
	g2Order            = saferith.ModulusFromNat(new(saferith.Nat).Mul(g2SubGroupOrder.Nat(), g2Cofactor, -1))
)

var _ curves.Curve = (*G2)(nil)

type G2 struct {
	_ ds.Incomparable
}

func g2Init() {
	g2Instance = G2{}
}

func NewG2() *G2 {
	g2InitOnce.Do(g2Init)
	return &g2Instance
}

// === Basic Methods.

func (*G2) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*G2) Contains(e curves.Point) bool {
	//TODO implement me
	panic("implement me")
}

func (*G2) Iter() iter.Seq[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*G2) Operators() []algebra.BinaryOperator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (c *G2) Unwrap() curves.Curve {
	return c
}

func (*G2) IsDefinedUnder(operator algebra.BinaryOperator[curves.Point]) bool {
	//TODO implement me
	panic("implement me")
}

func (*G2) Op(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], ys ...algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*G2) Addition() algebra.Addition[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*G2) ModuleScalarRing() algebra.ModuleBaseRing[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*G2) AlgebraicVarietyBaseField() algebra.AlgebraicVarietyBaseField[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*G2) VectorSpaceScalarField() algebra.VectorSpaceBaseField[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (c *G2) BasePoint() curves.Point {
	return c.Generator()
}

func (*G2) DLog(b, x algebra.CyclicGroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (*G2) ElementSize() int {
	panic("implement me")
}

func (*G2) WideElementSize() int {
	panic("implement me")
}

func (*G2) SuperGroupOrder() *saferith.Modulus {
	return g2Order
}

func (*G2) Name() string {
	return NameG2
}

func (*G2) Order() *saferith.Modulus {
	return bls12381SubGroupOrder
}

func (c *G2) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*G2) Random(prng io.Reader) (curves.Point, error) {
	result := new(PointG2)
	ok := result.V.SetRandom(prng)
	if ok != 1 {
		return nil, errs.NewRandomSample("point g2")
	}

	return result, nil
}

func (*G2) HashToFieldElements(count int, dstPrefix string, msg []byte) (u []curves.BaseFieldElement, err error) {
	out := make([]bls12381Impl.Fp2, count)
	h2c.HashToField(out[:], bls12381Impl.G2CurveHasherParams{}, dstPrefix+Hash2CurveSuiteG2, msg)

	u = make([]curves.BaseFieldElement, count)
	for i := range out {
		v := new(BaseFieldElementG2)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (c *G2) HashToScalars(count int, dstPrefix string, msg []byte) (u []curves.Scalar, err error) {
	out := make([]bls12381Impl.Fq, count)
	h2c.HashToField(out[:], bls12381Impl.G2CurveHasherParams{}, dstPrefix+Hash2CurveScalarSuiteG2, msg)

	u = make([]curves.Scalar, count)
	for i := range out {
		s := &Scalar{G: c}
		s.V.Set(&out[i])
		u[i] = s
	}

	return u, nil
}

func (c *G2) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuiteG2, input)
}

func (*G2) HashWithDst(dstPrefix string, input []byte) (curves.Point, error) {
	result := new(PointG2)
	result.V.Hash(dstPrefix, input)
	return result, nil
}

func (*G2) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0pt, ok0 := x0.(*PointG2)
	if !ok0 {
		panic("x0 is not a non-empty BLS12381 G2 element")
	}
	x1pt, ok1 := x1.(*PointG2)
	if !ok1 {
		panic("x1 is ot a non-empty BLS12381 G2 element")
	}
	sPt := new(PointG2)
	sPt.V.Select(choice, &x0pt.V, &x1pt.V)
	return sPt
}

// === Additive Groupoid Methods.

func (*G2) Add(x algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Monoid Methods.

func (*G2) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (*G2) AdditiveIdentity() curves.Point {
	result := new(PointG2)
	result.V.SetIdentity()
	return result
}

// === Group Methods.

func (*G2) CoFactor() *saferith.Nat {
	return g2Cofactor
}

// === Additive Group Methods.

func (*G2) Sub(x algebra.AdditiveGroupElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Cyclic Group Methods.

func (*G2) Generator() curves.Point {
	result := new(PointG2)
	result.V.SetGenerator()
	return result
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

func (c *G2) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
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

	if xx.V.IsZero() == 1 && yy.V.IsZero() == 1 {
		return c.AdditiveIdentity(), nil
	}

	result := new(PointG2)
	if ok := result.V.SetAffine(&xx.V, &yy.V); ok != 1 {
		return nil, errs.NewFailed("invalid coordinates")
	}

	return result, nil
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

func (*G2) FrobeniusEndomorphism(p curves.Point) curves.Point {
	//pp, ok := p.(*PointG2)
	//if !ok {
	//	panic("given point is not of the right type")
	//}
	//x := pp.AffineX()
	//y := pp.AffineY()
	//characteristic := NewBaseFieldG2().Characteristic()
	//result, err := c.NewPoint(x.Exp(characteristic), y.Exp(characteristic))
	//if err != nil {
	//	panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	//}
	//return result
	panic("not implemented")
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
	return bls12381SubGroupOrder
}

func (c *G2) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*G2) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]bls12381Impl.G2Point, len(points))
	nScalars := make([][]byte, len(scalars))
	for i, pt := range points {
		pp, ok := pt.(*PointG2)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointBls12381G2", reflect.TypeOf(pt).Name())
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
	value := new(PointG2)
	err := pointsImpl.MultiScalarMul[*bls12381Impl.Fp2](&value.V, nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}
	return value, nil
}

func (*G2) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	panic("not implemented")
}
