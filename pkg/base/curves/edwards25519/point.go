package edwards25519

import (
	"crypto/subtle"
	"encoding"
	"encoding/json"

	filippo "filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var _ curves.Point = (*Point)(nil)
var _ curves.ExtendedCoordinates = (*Point)(nil)
var _ encoding.BinaryMarshaler = (*Point)(nil)
var _ encoding.BinaryUnmarshaler = (*Point)(nil)
var _ json.Unmarshaler = (*Point)(nil)

type Point struct {
	V *filippo.Point

	_ types.Incomparable
}

func NewPoint() *Point {
	return &Point{V: filippo.NewIdentityPoint()}
}

// === Basic Methods.

func (p *Point) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*Point)
	if ok {
		// We would like to check that the point (X/Z, Y/Z) is equal to
		// the point (X'/Z', Y'/Z') without converting into affine
		// coordinates (x, y) and (x', y'), which requires two inversions.
		// We have that X = xZ and X' = x'Z'. Thus, x = x' is equivalent to
		// (xZ)Z' = (x'Z')Z, and similarly for the y-coordinate.
		return p.V.Equal(r.V) == 1
	} else {
		return false
	}
}

func (p *Point) Clone() curves.Point {
	return &Point{
		V: filippo.NewIdentityPoint().Set(p.V),
	}
}

// === Groupoid Methods.

func (p *Point) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *Point) OperateIteratively(q curves.Point, n *saferith.Nat) curves.Point {
	return p.ApplyAdd(q, n)
}

func (p *Point) Order() *saferith.Modulus {
	if p.IsIdentity() {
		return saferith.ModulusFromUint64(0)
	}
	q := p.Clone()
	order := new(saferith.Nat).SetUint64(1)
	for !q.IsIdentity() {
		q = q.Add(p)
		utils.Saferith.NatIncrement(order)
	}
	return saferith.ModulusFromNat(order)
}

// === Additive Groupoid Methods.

func (p *Point) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs in nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		return &Point{V: filippo.NewIdentityPoint().Add(p.V, r.V)}
	} else {
		panic("rhs in not PointEd25519")
	}
}

func (p *Point) ApplyAdd(q curves.Point, n *saferith.Nat) curves.Point {
	return p.Add(q.ScalarMul(NewScalarField().Element().SetNat(n)))
}

func (p *Point) Double() curves.Point {
	return &Point{V: filippo.NewIdentityPoint().Add(p.V, p.V)}
}

func (p *Point) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (p *Point) IsIdentity() bool {
	return p.Equal(NewCurve().Identity())
}

// === Additive Monoid Methods.

func (p *Point) IsAdditiveIdentity() bool {
	return p.IsIdentity()
}

// === Group Methods.

func (p *Point) Inverse() curves.Point {
	return &Point{V: filippo.NewIdentityPoint().Negate(p.V)}
}

func (p *Point) IsInverse(of curves.Point) bool {
	return p.Operate(of).IsIdentity()
}

// === Additive Group Methods.

func (p *Point) AdditiveInverse() curves.Point {
	return p.Inverse()
}

func (p *Point) IsAdditiveInverse(of curves.Point) bool {
	return p.IsInverse(of)
}

func (p *Point) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs in nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		rTmp := filippo.NewIdentityPoint().Negate(r.V)
		return &Point{V: filippo.NewIdentityPoint().Add(p.V, rTmp)}
	} else {
		panic("rhs in not PointEd25519")
	}
}

func (p *Point) ApplySub(q curves.Point, n *saferith.Nat) curves.Point {
	return p.Sub(q.ScalarMul(NewScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *Point) ScalarMul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs in nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		value := filippo.NewIdentityPoint().ScalarMult(r.V, p.V)
		return &Point{V: value}
	} else {
		panic("rhs in not ScalarEd25519")
	}
}

// === Curve Methods.

func (*Point) Curve() curves.Curve {
	return NewCurve()
}

func (p *Point) Neg() curves.Point {
	return p.Inverse()
}

func (p *Point) IsNegative() bool {
	return p.AffineY().Bytes()[0]&1 == 1
}

func (p *Point) ClearCofactor() curves.Point {
	return &Point{
		V: filippo.NewIdentityPoint().MultByCofactor(p.V),
	}
}

func (p *Point) IsSmallOrder() bool {
	// pBytes := p.ToAffineCompressed()
	// pHex := hex.EncodeToString(pBytes)

	// for _, smallOrderAffinecurves.Point[Edwards25519] := range []string{
	// 	"0100000000000000000000000000000000000000000000000000000000000000",
	// 	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	// 	"0000000000000000000000000000000000000000000000000000000000000080",
	// 	"0000000000000000000000000000000000000000000000000000000000000000",
	// 	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	// 	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	// 	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	// 	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	// } {
	// 	if pHex == smallOrderAffinecurves.Point[Edwards25519] {
	// 		return true
	// 	}
	// }
	// return false

	// performance difference is negligible
	return p.ClearCofactor().IsIdentity()
}

func (p *Point) IsTorsionElement(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsIdentity()
}

// === Coordinates.

func (p *Point) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *Point) AffineX() curves.BaseFieldElement {
	x, _, z, _ := p.V.ExtendedCoordinates()
	recip := new(field.Element).Invert(z)
	xx := new(field.Element).Multiply(x, recip)
	return &BaseFieldElement{
		V: xx,
	}
}

func (p *Point) AffineY() curves.BaseFieldElement {
	_, y, z, _ := p.V.ExtendedCoordinates()
	recip := new(field.Element).Invert(z)
	y.Multiply(y, recip)
	return &BaseFieldElement{
		V: y,
	}
}

func (p *Point) ExtendedX() curves.BaseFieldElement {
	x, _, _, _ := p.V.ExtendedCoordinates()
	return &BaseFieldElement{
		V: x,
	}
}

func (p *Point) ExtendedY() curves.BaseFieldElement {
	_, y, _, _ := p.V.ExtendedCoordinates()
	return &BaseFieldElement{
		V: y,
	}
}

func (p *Point) ExtendedZ() curves.BaseFieldElement {
	_, _, z, _ := p.V.ExtendedCoordinates()
	return &BaseFieldElement{
		V: z,
	}
}

func (p *Point) ExtendedT() curves.BaseFieldElement {
	_, _, _, t := p.V.ExtendedCoordinates()
	return &BaseFieldElement{
		V: t,
	}
}

// === Serialisation.

func (p *Point) ToAffineCompressed() []byte {
	return p.V.Bytes()
}

func (p *Point) ToAffineUncompressed() []byte {
	x, y, z, _ := p.V.ExtendedCoordinates()
	recip := new(field.Element).Invert(z)
	x.Multiply(x, recip)
	y.Multiply(y, recip)
	var out [64]byte
	copy(out[:32], x.Bytes())
	copy(out[32:], y.Bytes())
	return out[:]
}

func (*Point) FromAffineCompressed(inBytes []byte) (curves.Point, error) {
	pt, err := filippo.NewIdentityPoint().SetBytes(inBytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "set bytes method failed")
	}
	return &Point{V: pt}, nil
}

func (*Point) FromAffineUncompressed(inBytes []byte) (curves.Point, error) {
	if len(inBytes) != base.WideFieldBytes {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	if subtle.ConstantTimeCompare(inBytes, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) == 1 {
		return &Point{V: filippo.NewIdentityPoint()}, nil
	}
	x, err := new(field.Element).SetBytes(inBytes[:base.FieldBytes])
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "x")
	}
	y, err := new(field.Element).SetBytes(inBytes[base.FieldBytes:])
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "y")
	}
	z := new(field.Element).One()
	t := new(field.Element).Multiply(x, y)
	value, err := filippo.NewIdentityPoint().SetExtendedCoordinates(x, y, z, t)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "set extended coordinates")
	}
	return &Point{V: value}, nil
}

func (p *Point) MarshalBinary() ([]byte, error) {
	res := impl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *Point) UnmarshalBinary(input []byte) error {
	pt, err := impl.UnmarshalBinary(p.FromAffineCompressed, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal binary")
	}
	name, _, err := impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != p.Curve().Name() {
		return errs.NewInvalidType("name %s is not supported", name)
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.V = ppt.V
	return nil
}

func (p *Point) MarshalJSON() ([]byte, error) {
	res, err := impl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *Point) UnmarshalJSON(input []byte) error {
	pt, err := impl.UnmarshalJson(p.FromAffineCompressed, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	name, _, err := impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != p.Curve().Name() {
		return errs.NewInvalidType("name %s is not supported", name)
	}
	P, ok := pt.(*Point)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V = P.V
	return nil
}
