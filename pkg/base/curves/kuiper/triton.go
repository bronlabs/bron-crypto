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

const NameTriton = "Triton"

var (
	tritonInitOnce    sync.Once
	tritonInstance    Triton
	tritonCoFactor, _ = new(saferith.Nat).SetHex(strings.ToUpper("24000000000024000130e0000d7f70e4a803ca76f439266f443f9a5d3a8a6c7be4a7d5fe91447fd6a8a7e928a00867971ffffcd300000001"))
	tritonOrder, _    = saferith.ModulusFromHex(strings.ToUpper("510000000000a200055bf0008dbd8160e427fd21090885b8178b80a1ad26266043fe49f67cbfaa265b8e18f095703cf67eaccd4d3108df4de87c3dc0affd96ff302ca886826cb295b868bd5e1c7f5c01268b7b977320e964c31debf42e2e95c7e9b0d4bc01788743ffff9a600000001"))
)

var _ curves.Curve = (*Triton)(nil)

type Triton struct {
	hash2curve.CurveHasher

	_ ds.Incomparable
}

func tritonInit() {
	tritonInstance = Triton{}
	//tritonInstance.CurveHasher = hash2curve.NewCurveHasherSha256(
	//	curves.Curve(&tritonInstance),
	//	base.HASH2CURVE_APP_TAG,
	//	hash2curve.DstTagSswu,
	//)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (*Triton) SetHasherAppTag(appTag string) {
	//c.CurveHasher = hash2curve.NewCurveHasherSha256(
	//	curves.Curve(&tritonInstance),
	//	appTag,
	//	hash2curve.DstTagSswu,
	//)
	// TODO: not implemented
}

func NewTriton() *Triton {
	tritonInitOnce.Do(tritonInit)
	return &tritonInstance
}

// === Basic Methods.

func (*Triton) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*Triton) Contains(e curves.Point) bool {
	//TODO implement me
	panic("implement me")
}

func (*Triton) Iterator() ds.Iterator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*Triton) Operators() []algebra.BinaryOperator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (c *Triton) Unwrap() curves.Curve {
	return c
}

func (*Triton) IsDefinedUnder(operator algebra.BinaryOperator[curves.Point]) bool {
	//TODO implement me
	panic("implement me")
}

func (*Triton) Op(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], ys ...algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Triton) Addition() algebra.Addition[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*Triton) ModuleScalarRing() algebra.ModuleBaseRing[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*Triton) AlgebraicVarietyBaseField() algebra.AlgebraicVarietyBaseField[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*Triton) VectorSpaceScalarField() algebra.VectorSpaceBaseField[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (c *Triton) BasePoint() curves.Point {
	return c.Generator()
}

func (*Triton) DLog(b, x algebra.CyclicGroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (*Triton) ElementSize() int {
	panic("implement me")
}

func (*Triton) WideElementSize() int {
	panic("implement me")
}

func (*Triton) SuperGroupOrder() *saferith.Modulus {
	return tritonOrder
}

func (*Triton) Name() string {
	return NameTriton
}

func (*Triton) Order() *saferith.Modulus {
	return impl.FqModulus
}

func (c *Triton) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*Triton) Random(prng io.Reader) (curves.Point, error) {
	panic("not implemented")
	//pt := new(bimpl.G2)
	//u0, err := NewTritonBaseField().Random(prng)
	//if err != nil {
	//	return nil, errs.WrapRandomSample(err, "couldn't generate random field element")
	//}
	//u1, err := NewBaseFieldG2().Random(prng)
	//if err != nil {
	//	return nil, errs.WrapRandomSample(err, "couldn't generate random field element")
	//}
	//u0fe, ok0 := u0.(*BaseFieldElementG2)
	//u1fe, ok1 := u1.(*BaseFieldElementG2)
	//if !ok0 || !ok1 {
	//	return nil, errs.WrapHashing(err, "Cast to BLS12381 G1 field elements failed")
	//}
	//pt.Map(u0fe.V, u1fe.V)
	//return &TritonPoint{V: pt}, nil
}

func (c *Triton) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (*Triton) HashWithDst(input, dst []byte) (curves.Point, error) {
	panic("not implemented")
	//pt := new(bimpl.G2)
	//u, err := NewTriton().HashToFieldElements(2, input, dst)
	//if err != nil {
	//	return nil, errs.WrapHashing(err, "hash to field element of BLS12381 G2 failed")
	//}
	//u0, ok0 := u[0].(*TritonBaseFieldElement)
	//u1, ok1 := u[1].(*TritonBaseFieldElement)
	//if !ok0 || !ok1 {
	//	return nil, errs.WrapHashing(err, "Cast to BLS12381 G2 field elements failed")
	//}
	//pt.Map(u0.V, u1.V)
	//return &TritonPoint{V: pt}, nil
}

func (*Triton) Select(choice bool, x0, x1 curves.Point) curves.Point {
	x0pt, ok0 := x0.(*TritonPoint)
	x1pt, ok1 := x1.(*TritonPoint)
	if !ok0 || !ok1 {
		panic("Not a BLS12381 G1 point")
	}
	sPt := new(TritonPoint)
	sPt.V.CMove(&x0pt.V, &x1pt.V, utils.BoolTo[uint64](choice))
	return sPt
}

// === Additive Groupoid Methods.

func (*Triton) Add(x algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Monoid Methods.

func (*Triton) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (*Triton) AdditiveIdentity() curves.Point {
	return &TritonPoint{
		V: *new(impl.TritonPoint).Identity(),
	}
}

// === Group Methods.

func (*Triton) CoFactor() *saferith.Nat {
	return tritonCoFactor
}

// === Additive Group Methods.

func (*Triton) Sub(x algebra.AdditiveGroupElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Cyclic Group Methods.

func (*Triton) Generator() curves.Point {
	return &TritonPoint{
		V: *new(impl.TritonPoint).Generator(),
	}
}

// === Variety Methods.

func (*Triton) Dimension() int {
	return 1
}

func (*Triton) Discriminant() *saferith.Int {
	panic("not implemented")
}

// === Algebraic Curve Methods.

func (*Triton) BaseField() curves.BaseField {
	return NewTritonBaseField()
}

func (*Triton) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}
	xx, ok := x.(*TritonBaseFieldElement)
	if !ok {
		return nil, errs.NewType("x is not of the right type")
	}
	yy, ok := y.(*TritonBaseFieldElement)
	if !ok {
		return nil, errs.NewType("y is not of the right type")
	}

	value := new(impl.TritonPoint)
	value.X.Set(&xx.V)
	value.Y.Set(&yy.V)
	value.Z.SetOne()
	return &TritonPoint{V: *value}, nil
}

// === Elliptic Curve Methods.

func (c *Triton) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (*Triton) ScalarField() curves.ScalarField {
	return NewTritonScalarField()
}

func (c *Triton) Point() curves.Point {
	return c.Element()
}

func (c *Triton) Scalar() curves.Scalar {
	return c.ScalarField().Element()
}

func (c *Triton) BaseFieldElement() curves.BaseFieldElement {
	return c.BaseField().Zero()
}

func (c *Triton) FrobeniusEndomorphism(p curves.Point) curves.Point {
	pp, ok := p.(*TritonPoint)
	if !ok {
		panic("given point is not of the right type")
	}
	x := pp.AffineX()
	y := pp.AffineY()
	characteristic := NewTritonBaseField().Characteristic()
	result, err := c.NewPoint(x.Exp(characteristic), y.Exp(characteristic))
	if err != nil {
		panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	}
	return result
}

func (*Triton) TraceOfFrobenius() *saferith.Int {
	// TODO: find number of rational points
	panic("not implemented.")
}

func (*Triton) JInvariant() *saferith.Int {
	return new(saferith.Int).SetUint64(0)
}

// === Prime SubGroup Methods.

func (*Triton) SubGroupOrder() *saferith.Modulus {
	return impl.FqModulus
}

func (c *Triton) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*Triton) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	panic("not implemented")
	//nPoints := make([]*bimpl.G2, len(points))
	//nScalars := make([]*limb4.FieldValue, len(scalars))
	//for i, pt := range points {
	//	pp, ok := pt.(*TritonPoint)
	//	if !ok {
	//		return nil, errs.NewFailed("invalid point type %s, expected PointBls12381G2", reflect.TypeOf(pt).Name())
	//	}
	//	nPoints[i] = &pp.V
	//}
	//for i, sc := range scalars {
	//	s, ok := sc.(*PlutoTritonScalar)
	//	if !ok {
	//		return nil, errs.NewFailed("invalid scalar type %s, expected ScalarBls12381", reflect.TypeOf(sc).Name())
	//	}
	//	nScalars[i] = s.V
	//}
	//value, err := new(bimpl.G2).SumOfProducts(nPoints, nScalars)
	//if err != nil {
	//	return nil, errs.WrapFailed(err, "multiscalar multiplication")
	//}
	//return &TritonPoint{V: value}, nil
}

func (*Triton) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	panic("not implemented")
}
