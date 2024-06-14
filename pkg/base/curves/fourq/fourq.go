package fourq

import (
	"io"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/fourq/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/mappings/elligator2"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

const Name = "FourQ"

var (
	fourQCurveInitOnce sync.Once
	fourQCurveInstance Curve

	//scOne, _   = filippo.NewScalar().SetCanonicalBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	//scMinusOne = [32]byte{236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}
	//
	//subgroupOrder, _  = saferith.ModulusFromHex(strings.ToUpper("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"))
	//cofactor          = new(saferith.Nat).SetUint64(8)
	//groupOrder        = saferith.ModulusFromNat(new(saferith.Nat).Mul(subgroupOrder.Nat(), cofactor, subgroupOrder.Nat().AnnouncedLen()+cofactor.AnnouncedLen()))
	//baseFieldOrder, _ = saferith.ModulusFromHex(strings.ToUpper("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"))
	//elementSize       = 32
	//
	//// d is a constant in the curve equation.
	//d, _ = new(filippo_field.Element).SetBytes([]byte{
	//	0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
	//	0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
	//	0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
	//	0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
	//}).
)

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	hash2curve.CurveHasher
	*elligator2.Params

	_ ds.Incomparable
}

func fourQInit() {
	fourQCurveInstance = Curve{}
	//fourQCurveInstance.CurveHasher = hash2curve.NewCurveHasherSha512(
	//	curves.Curve(&fourQCurveInstance),
	//	base.HASH2CURVE_APP_TAG,
	//	hash2curve.DstTagElligator2,
	//)
	//fourQCurveInstance.Params = elligator2.NewParams(&fourQCurveInstance, true)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (*Curve) SetHasherAppTag(appTag string) {
	//c.CurveHasher = hash2curve.NewCurveHasherSha512(
	//	curves.Curve(&fourQCurveInstance),
	//	appTag,
	//	hash2curve.DstTagElligator2,
	//)
}

func NewCurve() *Curve {
	fourQCurveInitOnce.Do(fourQInit)
	return &fourQCurveInstance
}

func (*Curve) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Contains(e curves.Point) bool {
	_, ok := e.(*Point)
	return ok
}

func (*Curve) Iterator() ds.Iterator[curves.Point] {
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
	return 32
}

func (*Curve) WideElementSize() int {
	panic("implement me")
}

func (*Curve) SuperGroupOrder() *saferith.Modulus {
	panic("implement me")
}

func (*Curve) Name() string {
	return Name
}

func (*Curve) Order() *saferith.Modulus {
	panic("implement me")
}

func (c *Curve) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*Curve) Random(prng io.Reader) (curves.Point, error) {
	//u0, err := c.BaseField().Random(prng)
	//if err != nil {
	//	return nil, errs.WrapRandomSample(err, "could not read random bytes (to be used as uniform field element)")
	//}
	//u1, err := c.BaseField().Random(prng)
	//if err != nil {
	//	return nil, errs.WrapFailed(err, "could not generate random field element")
	//}
	//p0 := c.Map(u0)
	//p1 := c.Map(u1)
	//return p0.Add(p1).ClearCofactor(), nil
	panic("implement me")
}

func (c *Curve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (*Curve) HashWithDst(input, dst []byte) (curves.Point, error) {
	panic("implement me")
	//u, err := c.HashToFieldElements(2, input, dst)
	//if err != nil {
	//	return nil, errs.WrapHashing(err, "could not hash to field elements in ed25519")
	//}
	//p0 := c.Map(u[0])
	//p1 := c.Map(u[1])
	//return p0.Add(p1).ClearCofactor(), nil
}

// Map a an ed25519 field element into a point on ed25519 curve, using the
// Elligator2 map to curve25519 and a bidirectional map.
// See https://datatracker.ietf.org/doc/html/rfc9380#section-6.7.1
func (*Curve) Map(u curves.BaseFieldElement) curves.Point {
	panic("implement me")
	//xn, xd, yn, yd := c.MapToCurveElligator2edwards25519(u)
	//// To projective coordinates.
	//x := xn.Mul(yd)
	//y := yn.Mul(xd)
	//z := xd.Mul(yd)
	//// To extended coordinates.
	//xEd, okx := x.Mul(z).(*BaseFieldElement)
	//yEd, oky := y.Mul(z).(*BaseFieldElement)
	//zEd, okz := z.Square().(*BaseFieldElement)
	//tEd, okt := x.Mul(y).(*BaseFieldElement)
	//if !okx || !oky || !okz || !okt {
	//	panic("could not convert to extended coordinates")
	//}
	//p, err := filippo.NewIdentityPoint().SetExtendedCoordinates(xEd.V, yEd.V, zEd.V, tEd.V)
	//if err != nil {
	//	panic(err)
	//}
	//return &Point{V: p}
}

func (*Curve) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0Ed, ok0 := x0.(*Point)
	if !ok0 || x0Ed.V == nil {
		panic("x0 is not a non-empty edwards25519 point")
	}
	x1Ed, ok1 := x1.(*Point)
	if !ok1 || x1Ed.V == nil {
		panic("x1 is not a non-empty edwards25519 point")
	}

	return &Point{V: new(impl.ExtendedPoint).CMove(x0Ed.V, x1Ed.V, choice)}
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

func (*Curve) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("not implemented")
}

// === Additive Monoid Methods.

func (*Curve) AdditiveIdentity() curves.Point {
	return &Point{
		V: new(impl.ExtendedPoint).Identity(),
	}
}

// === Group Methods.

func (*Curve) CoFactor() *saferith.Nat {
	return new(saferith.Nat).SetUint64(8)
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
		V: new(impl.ExtendedPoint).Generator(),
	}
}

// === Variety Methods.

func (*Curve) Dimension() int {
	return 1
}

func (*Curve) Discriminant() *saferith.Int {
	panic("implement me")
}

// === Algebraic Curve Methods.

func (*Curve) BaseField() curves.BaseField {
	return NewBaseField()
}

func (*Curve) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
	panic("implement me")
}

// === Elliptic Curve Methods.

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

func (*Curve) FrobeniusEndomorphism(p curves.Point) curves.Point {
	panic("implement me")
}

func (*Curve) TraceOfFrobenius() *saferith.Int {
	panic("implement me")
}

func (*Curve) JInvariant() *saferith.Int {
	panic("implement me")
}

// === Prime SubGroup Methods.

func (*Curve) SubGroupOrder() *saferith.Modulus {
	order, err := new(saferith.Nat).SetHex(strings.ToUpper("29cbc14e5e0a72f05397829cbc14e5dfbd004dfe0f79992fb2540ec7768ce7"))
	if err != nil {
		panic(err)
	}
	return saferith.ModulusFromNat(order)
}

func (c *Curve) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	panic("implement me")
}

func (*Curve) DeriveFromAffineX(x curves.BaseFieldElement) (p1, p2 curves.Point, err error) {
	panic("implement me")
}
