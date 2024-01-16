package edwards25519

import (
	"io"
	"reflect"
	"strings"
	"sync"

	filippo "filippo.io/edwards25519"
	filippo_field "filippo.io/edwards25519/field"
	ed "github.com/bwesterb/go-ristretto/edwards25519"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashing "github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve"
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
	hashing.CurveHasher

	_ types.Incomparable
}

func ed25519Init() {
	edwards25519Instance = Curve{}
	edwards25519Instance.CurveHasher = hashing.NewCurveHasherSha512(
		curves.Curve(&edwards25519Instance),
		base.HASH2CURVE_APP_TAG,
		hashing.DST_TAG_ELLIGATOR2,
	)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *Curve) SetHasherAppTag(appTag string) {
	c.CurveHasher = hashing.NewCurveHasherSha512(
		curves.Curve(&edwards25519Instance),
		appTag,
		hashing.DST_TAG_ELLIGATOR2,
	)
}

func NewCurve() *Curve {
	edwards25519Initonce.Do(ed25519Init)
	return &edwards25519Instance
}

// === Basic Methods.

func (*Curve) Name() string {
	return Name
}

func (*Curve) Order() *saferith.Modulus {
	return groupOrder
}

func (c *Curve) Element() curves.Point {
	return c.Identity()
}

func (c *Curve) OperateOver(operator algebra.Operator, ps ...curves.Point) (curves.Point, error) {
	if operator != algebra.PointAddition {
		return nil, errs.NewInvalidType("operator %v is not supported", operator)
	}
	current := c.Identity()
	for _, p := range ps {
		current = current.Operate(p)
	}
	return current, nil
}

func (*Curve) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.PointAddition}
}

func (c *Curve) Random(prng io.Reader) (curves.Point, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var fieldElement [base.FieldBytes]byte
	_, err := prng.Read(fieldElement[:])
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not read random bytes (to be used as uniform field element)")
	}
	return c.Map(fieldElement[:]), nil
}

// Map a little-endian encoding of an ed25519 field element into a point on
// ed25519 curve, using the Elligator2 map to curve25519 and a bidirectional
// map to get to ed25519.
//
// The encoding follows `element = Σ_{i=0}^{k-1} (input[i] << 8*i)`.
// Contrary to most curves (which often require checking if the field element is
// reduced), this encoding is possible thanks to the proximity of the field
// order to a power of 2. As a nice consequence, we don't need to use `SetBytesWide`
// to reduce the bias of non-uniform sampling, as this direct method yields a small
// bias (< 2^-250) already.
//
// See https://datatracker.ietf.org/doc/html/rfc9380#section-6.7.1
func (*Curve) Map(fieldElement []byte) curves.Point {
	signBit := (fieldElement[31] & 0x80) >> 7
	fe := new(ed.FieldElement).SetBytes((*[base.FieldBytes]byte)(fieldElement))
	m1 := elligatorEncode(fe)
	return toEdwards(m1, signBit)
}

// Perform hashing to the ed25519 group using the Elligator2 mapping
//
// See https://datatracker.ietf.org/doc/html/rfc9380#section-6.7.1
func (c *Curve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (c *Curve) HashWithDst(input, dst []byte) (curves.Point, error) {
	buffer, err := NewCurve().ExpandMessage(base.FieldBytes, input, dst)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not hash to field elements in ed25519")
	}
	point := c.Map(buffer)
	return point, nil
}

// === Additive Groupoid Methods.

func (*Curve) Add(x curves.Point, ys ...curves.Point) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Monoid Methods.

func (*Curve) Identity() curves.Point {
	return &Point{
		V: filippo.NewIdentityPoint(),
	}
}

// === Additive Monoid Methods.

func (c *Curve) AdditiveIdentity() curves.Point {
	return c.Identity()
}

// === Group Methods.

func (*Curve) Cofactor() *saferith.Nat {
	return new(saferith.Nat).SetUint64(8)
}

// === Additive Group Methods.

func (*Curve) Sub(x curves.Point, ys ...curves.Point) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
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

func (*Curve) NewPoint(x, y curves.BaseFieldElement) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}

	xx, ok := x.(*BaseFieldElement)
	if !ok {
		return nil, errs.NewInvalidType("x is not the right type")
	}
	yy, ok := y.(*BaseFieldElement)
	if !ok {
		return nil, errs.NewInvalidType("y is not the right type")
	}

	// check is identity
	xElem := new(ed.FieldElement).SetBigInt(xx.Nat().Big())
	yElem := new(ed.FieldElement).SetBigInt(yy.Nat().Big())

	var data [32]byte
	var affine [64]byte
	xElem.BytesInto(&data)
	copy(affine[:32], data[:])
	yElem.BytesInto(&data)
	copy(affine[32:], data[:])
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
	characteristic := NewBaseFieldElement(0).SetNat(NewBaseField().Characteristic())
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

func (c *Curve) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
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
		return nil, nil, errs.NewInvalidType("x is not an edwards25519 base field element")
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
		return nil, nil, errs.NewInvalidCoordinates("edwards25519: invalid point encoding")
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
