package edwards25519

import (
	"io"
	"iter"
	"reflect"
	"strings"
	"sync"

	filippo "filippo.io/edwards25519"
	filippo_field "filippo.io/edwards25519/field"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/mappings/elligator2"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
)

const Name = "edwards25519" // Compliant with Hash2curve (https://datatracker.ietf.org/doc/html/rfc9380)

var (
	edwards25519Initonce sync.Once
	edwards25519Instance Curve

	scOne, _   = filippo.NewScalar().SetCanonicalBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	scMinusOne = [32]byte{236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}

	subgroupOrder, _  = saferith.ModulusFromHex(strings.ToUpper("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"))
	cofactor          = new(saferith.Nat).SetUint64(8)
	groupOrder        = saferith.ModulusFromNat(new(saferith.Nat).Mul(subgroupOrder.Nat(), cofactor, subgroupOrder.Nat().AnnouncedLen()+cofactor.AnnouncedLen()))
	baseFieldOrder, _ = saferith.ModulusFromHex(strings.ToUpper("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"))
	elementSize       = 32

	// d is a constant in the curve equation.
	d, _ = new(filippo_field.Element).SetBytes([]byte{
		0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
		0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
		0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
		0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
	})
)

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	hash2curve.CurveHasher
	*elligator2.Params

	_ ds.Incomparable
}

func ed25519Init() {
	edwards25519Instance = Curve{}
	edwards25519Instance.CurveHasher = hash2curve.NewCurveHasherSha512(
		curves.Curve(&edwards25519Instance),
		base.HASH2CURVE_APP_TAG,
		hash2curve.DstTagElligator2,
	)
	edwards25519Instance.Params = elligator2.NewParams(&edwards25519Instance, true)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *Curve) SetHasherAppTag(appTag string) {
	c.CurveHasher = hash2curve.NewCurveHasherSha512(
		curves.Curve(&edwards25519Instance),
		appTag,
		hash2curve.DstTagElligator2,
	)
}

func NewCurve() *Curve {
	edwards25519Initonce.Do(ed25519Init)
	return &edwards25519Instance
}

func (*Curve) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Contains(e curves.Point) bool {
	edE, ok := e.(*Point)
	if !ok {
		return false
	}
	fp := &filippo.Point{}
	_, err := fp.SetBytes(edE.V.Bytes())
	return err == nil
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
	return elementSize
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
		return nil, errs.WrapRandomSample(err, "could not read random bytes (to be used as uniform field element)")
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

// Map a an ed25519 field element into a point on ed25519 curve, using the
// Elligator2 map to curve25519 and a bidirectional map.
// See https://datatracker.ietf.org/doc/html/rfc9380#section-6.7.1
func (c *Curve) Map(u curves.BaseFieldElement) curves.Point {
	xn, xd, yn, yd := c.MapToCurveElligator2edwards25519(u)
	// To projective coordinates.
	x := xn.Mul(yd)
	y := yn.Mul(xd)
	z := xd.Mul(yd)
	// To extended coordinates.
	xEd, okx := x.Mul(z).(*BaseFieldElement)
	yEd, oky := y.Mul(z).(*BaseFieldElement)
	zEd, okz := z.Square().(*BaseFieldElement)
	tEd, okt := x.Mul(y).(*BaseFieldElement)
	if !okx || !oky || !okz || !okt {
		panic("could not convert to extended coordinates")
	}
	p, err := filippo.NewIdentityPoint().SetExtendedCoordinates(xEd.V, yEd.V, zEd.V, tEd.V)
	if err != nil {
		panic(err)
	}
	return &Point{V: p}
}

func (c *Curve) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0Ed, ok0 := x0.(*Point)
	if !ok0 || x0Ed.V == nil {
		panic("x0 is not a non-empty edwards25519 point")
	}
	x1Ed, ok1 := x1.(*Point)
	if !ok1 || x1Ed.V == nil {
		panic("x1 is not a non-empty edwards25519 point")
	}
	sEd, okp := c.Element().(*Point)
	if !okp || sEd.V == nil {
		panic("curve.Element() not a non-empty edwards25519 point")
	}
	x0Ed_x, x0Ed_y, x0Ed_z, x0Ed_t := x0Ed.V.ExtendedCoordinates()
	x1Ed_x, x1Ed_y, x1Ed_z, x1Ed_t := x1Ed.V.ExtendedCoordinates()
	xEd := new(filippo_field.Element).Select(x1Ed_x, x0Ed_x, safecast.MustToInt(choice))
	yEd := new(filippo_field.Element).Select(x1Ed_y, x0Ed_y, safecast.MustToInt(choice))
	zEd := new(filippo_field.Element).Select(x1Ed_z, x0Ed_z, safecast.MustToInt(choice))
	tEd := new(filippo_field.Element).Select(x1Ed_t, x0Ed_t, safecast.MustToInt(choice))
	var err error
	sEd.V, err = sEd.V.SetExtendedCoordinates(xEd, yEd, zEd, tEd)
	if err != nil {
		panic(err)
	}
	return sEd
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
		V: filippo.NewIdentityPoint(),
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
		V: filippo.NewGeneratorPoint(),
	}
}

// === Variety Methods.

func (*Curve) Dimension() int {
	return 1
}

func (*Curve) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("1562fe9d5c16b700e197a60c9a6c11c0eb738987971858db4bfc83e985be241"))
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

	var affine [base.WideFieldBytes]byte
	copy(affine[:base.FieldBytes], xx.V.Bytes())
	copy(affine[base.FieldBytes:], yy.V.Bytes())
	return new(Point).FromAffineUncompressed(affine[:])
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
	x := pp.AffineX()
	y := pp.AffineY()
	characteristic := NewBaseField().Characteristic()
	result, err := c.NewPoint(x.Exp(characteristic), y.Exp(characteristic))
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
	nScalars := make([]*filippo.Scalar, len(scalars))
	nPoints := make([]*filippo.Point, len(points))
	for i, sc := range scalars {
		s, err := filippo.NewScalar().SetCanonicalBytes(bitstring.ReverseBytes(sc.Bytes()))
		if err != nil {
			return nil, errs.WrapSerialisation(err, "set canonical bytes")
		}
		nScalars[i] = s
	}
	for i, pt := range points {
		pp, ok := pt.(*Point)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointEd25519", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = pp.V
	}
	pt := filippo.NewIdentityPoint().MultiScalarMult(nScalars, nPoints)
	return &Point{V: pt}, nil
}

func (*Curve) DeriveFromAffineX(x curves.BaseFieldElement) (p1, p2 curves.Point, err error) {
	xc, ok := x.(*BaseFieldElement)
	if !ok {
		return nil, nil, errs.NewType("x is not an edwards25519 base field element")
	}

	feOne := new(filippo_field.Element).One()

	// -x² + y² = 1 + dx²y²
	// x² + dx²y² = x²(dy² + 1) = y² - 1
	// y² = (x² + 1) / (1 - dx²)

	// u = x² + 1
	x2 := new(filippo_field.Element).Square(xc.V)
	u := new(filippo_field.Element).Add(x2, feOne)

	// v = 1 - dx²
	dx2 := new(filippo_field.Element).Multiply(x2, d)
	v := dx2.Subtract(feOne, dx2)

	// x = +√(u/v)
	y, wasSquare := new(filippo_field.Element).SqrtRatio(u, v)
	if wasSquare == 0 {
		return nil, nil, errs.NewCoordinates("edwards25519: invalid point encoding")
	}
	yNeg := new(filippo_field.Element).Negate(y)
	yy := new(filippo_field.Element).Select(yNeg, y, int(y.Bytes()[31]>>7))

	p1e, err := filippo.NewIdentityPoint().SetExtendedCoordinates(xc.V, yy, feOne, new(filippo_field.Element).Multiply(xc.V, yy))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldnt set extended coordinates")
	}
	p1 = &Point{V: p1e}

	p2e, err := filippo.NewIdentityPoint().SetExtendedCoordinates(xc.V, yNeg, feOne, new(filippo_field.Element).Multiply(xc.V, new(filippo_field.Element).Negate(yy)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldnt set extended coordinates")
	}
	p2 = &Point{V: p2e}

	if p1.AffineY().IsEven() {
		return p1, p2, nil
	} else {
		return p2, p1, nil
	}
}
