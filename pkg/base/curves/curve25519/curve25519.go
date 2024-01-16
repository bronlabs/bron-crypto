package curve25519

import (
	"io"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"
	curve25519n "golang.org/x/crypto/curve25519"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashing "github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve"
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
	hashing.CurveHasher

	_ types.Incomparable
}

func curve25519Init() {
	curve25519Instance = Curve{}
	curve25519Instance.CurveHasher = hashing.NewCurveHasherSha512(
		curves.Curve(&curve25519Instance),
		base.HASH2CURVE_APP_TAG,
		hashing.DST_TAG_ELLIGATOR2,
	)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *Curve) SetHasherAppTag(appTag string) {
	c.CurveHasher = hashing.NewCurveHasherSha512(
		curves.Curve(&curve25519Instance),
		appTag,
		hashing.DST_TAG_ELLIGATOR2,
	)
}

func NewCurve() *Curve {
	curve25519Initonce.Do(curve25519Init)
	return &curve25519Instance
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

func (*Curve) Random(reader io.Reader) (curves.Point, error) {
	panic("not implemented")
}

func (*Curve) Hash(input []byte) (curves.Point, error) {
	panic("not implemented")
}

func (*Curve) HashWithDst(input, dst []byte) (curves.Point, error) {
	panic("not implemented")
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

func (*Curve) NewPoint(x, y curves.BaseFieldElement) (curves.Point, error) {
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
	characteristic := NewBaseFieldElement(0).SetNat(NewBaseField().Characteristic())
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

func (c *Curve) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	panic("not implemented")
}

func (*Curve) DeriveFromAffineX(x curves.BaseFieldElement) (p1, p2 curves.Point, err error) {
	panic("not implemented")
}
