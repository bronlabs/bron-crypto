package curve25519

import (
	"io"
	"iter"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"
	curve25519n "golang.org/x/crypto/curve25519"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/mappings/elligator2"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

const Name = "curve25519" // Compliant with Hash2curve (https://datatracker.ietf.org/doc/html/rfc9380)

var (
	curve25519Initonce sync.Once
	curve25519Instance Curve
	cofactor           = new(saferith.Nat).SetUint64(8)
	subgroupOrder, _   = saferith.ModulusFromHex(strings.ToUpper("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"))
	baseFieldOrder, _  = saferith.ModulusFromHex(strings.ToUpper("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"))
	groupOrder         = saferith.ModulusFromNat(new(saferith.Nat).Mul(subgroupOrder.Nat(), cofactor, subgroupOrder.Nat().AnnouncedLen()+cofactor.AnnouncedLen()))
)

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	hash2curve.CurveHasher
	*elligator2.Params
	_ ds.Incomparable
}

func curve25519Init() {
	curve25519Instance = Curve{}
	curve25519Instance.CurveHasher = hash2curve.NewCurveHasherSha512(
		curves.Curve(&curve25519Instance),
		base.HASH2CURVE_APP_TAG,
		hash2curve.DstTagElligator2,
	)
	curve25519Instance.Params = elligator2.NewParams(&curve25519Instance, true)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *Curve) SetHasherAppTag(appTag string) {
	c.CurveHasher = hash2curve.NewCurveHasherSha512(
		curves.Curve(&curve25519Instance),
		appTag,
		hash2curve.DstTagElligator2,
	)
}

func NewCurve() *Curve {
	curve25519Initonce.Do(curve25519Init)
	return &curve25519Instance
}

func (*Curve) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Contains(e curves.Point) bool {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Iter() iter.Seq[curves.Point] {
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
	panic("implement me")
}

func (*Curve) WideElementSize() int {
	panic("implement me")
}

func (*Curve) SuperGroupOrder() *saferith.Modulus {
	return groupOrder
}

func (*Curve) Name() string {
	return Name
}

func (*Curve) Order() *saferith.Modulus {
	return subgroupOrder
}

func (c *Curve) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (c *Curve) Random(prng io.Reader) (curves.Point, error) {
	u0, err := c.BaseField().Random(prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate random field element")
	}
	u1, err := c.BaseField().Random(prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate random field element")
	}
	p0 := c.Map(u0)
	p1 := c.Map(u1)
	return p0.Add(p1).ClearCofactor(), nil
}

func (c *Curve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (c *Curve) HashWithDst(input, dst []byte) (curves.Point, error) {
	u, err := c.HashToFieldElements(2, input, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not hash to field elements in ed25519")
	}
	p0 := c.Map(u[0])
	p1 := c.Map(u[1])
	return p0.Add(p1).ClearCofactor(), nil
}

// Map a curve25519 field element into a point on curve25519, using the Elligator2 map.
// See https://datatracker.ietf.org/doc/html/rfc9380#section-6.7.1
func (c *Curve) Map(u curves.BaseFieldElement) curves.Point {
	xn, xd, yn, yd := c.MapToCurveElligator2Curve25519(u)
	// To affine coordinates.
	x, _ := xn.Div(xd)
	y := yn.Mul(yd)
	p, err := c.NewPoint(x, y)
	if err != nil {
		panic(err)
	}
	return p
}

// Select returns x0 if choice is false, and x1 if choice is true.
func (*Curve) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0p, ok0 := x0.(*Point)
	if !ok0 {
		panic("x0 is not a curve25519 point")
	}
	x1p, ok1 := x1.(*Point)
	if !ok1 {
		panic("x1 is not a curve25519 point")
	}
	el := new(Point)
	ct.SliceSelect(choice, el.V[:], x0p.V[:], x1p.V[:])
	return el
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
	panic("implement me")
}

// === Additive Monoid Methods.

func (*Curve) AdditiveIdentity() curves.Point {
	return &Point{
		V: [32]byte{
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
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
	var result [32]byte
	copy(result[:], curve25519n.Basepoint)
	return &Point{
		V: result,
	}
}

// === Variety Methods.

func (*Curve) Dimension() int {
	return 1
}

func (*Curve) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("3724c21c200"))
	return new(saferith.Int).SetNat(result)
}

// === Algebraic Curve Methods.

func (*Curve) BaseField() curves.BaseField {
	return NewBaseField()
}

func (*Curve) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
	panic("not implemented")
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

func (c *Curve) FrobeniusEndomorphism(p curves.Point) curves.Point {
	pp, ok := p.(*Point)
	if !ok {
		panic("given point is not of the right type")
	}
	characteristic := NewBaseField().Characteristic()
	result, err := c.NewPoint(pp.AffineX().Exp(characteristic), pp.AffineY().Exp(characteristic))
	if err != nil {
		panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	}
	return result
}

func (*Curve) TraceOfFrobenius() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("56c143fbfba334948229e71bacc4801f4321f1a7c4591336f27d7903cb215317"))
	return new(saferith.Int).SetNat(result)
}

func (*Curve) JInvariant() *saferith.Int {
	v, _ := new(saferith.Nat).SetHex(strings.ToUpper("a6f7cef517bce6b2c09318d2e7ae9f7a"))
	return new(saferith.Int).SetNat(v).Neg(1)
}

// === Prime SubGroup Methods.

func (*Curve) SubGroupOrder() *saferith.Modulus {
	return subgroupOrder
}

func (c *Curve) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	panic("not implemented")
}

func (*Curve) DeriveFromAffineX(x curves.BaseFieldElement) (p1, p2 curves.Point, err error) {
	panic("not implemented")
}
