package k256

import (
	"encoding"
	"encoding/binary"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	k256impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fp"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var _ curves.Point = (*Point)(nil)
var _ curves.ProjectiveCurveCoordinates = (*Point)(nil)
var _ encoding.BinaryMarshaler = (*Point)(nil)
var _ encoding.BinaryUnmarshaler = (*Point)(nil)
var _ json.Unmarshaler = (*Point)(nil)

type Point struct {
	V *impl.EllipticPoint

	_ ds.Incomparable
}

func NewPoint() *Point {
	return NewCurve().Identity().(*Point)
}

// === Basic Methods.

func (p *Point) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*Point)
	if ok {
		return p.V.Equal(r.V) == 1
	} else {
		return false
	}
}

func (p *Point) Clone() curves.Point {
	return &Point{
		V: k256impl.PointNew().Set(p.V),
	}
}

// === Groupoid Methods.

func (p *Point) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *Point) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.Mul(NewCurve().Scalar().SetNat(n))
}

func (p *Point) Order() *saferith.Modulus {
	if p.IsIdentity() {
		return saferith.ModulusFromUint64(0)
	}
	q := p.Clone()
	order := new(saferith.Nat).SetUint64(1)
	for !q.IsIdentity() {
		q = q.Add(p)
		utils.IncrementNat(order)
	}
	return saferith.ModulusFromNat(order)
}

// === Additive Groupoid Methods.

func (p *Point) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		value := k256impl.PointNew().Add(p.V, r.V)
		return &Point{V: value}
	} else {
		panic("rhs is not PointK256")
	}
}

func (p *Point) ApplyAdd(q curves.Point, n *saferith.Nat) curves.Point {
	return p.Add(q.Mul(NewScalarField().Element().SetNat(n)))
}

func (p *Point) Double() curves.Point {
	value := k256impl.PointNew().Double(p.V)
	return &Point{V: value}
}

func (p *Point) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (p *Point) IsIdentity() bool {
	return p.V.IsIdentity()
}

// === Additive Monoid Methods.

func (p *Point) IsAdditiveIdentity() bool {
	return p.IsIdentity()
}

// === Group Methods.

func (p *Point) Inverse() curves.Point {
	value := k256impl.PointNew().Neg(p.V)
	return &Point{V: value}
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
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		value := k256impl.PointNew().Sub(p.V, r.V)
		return &Point{V: value}
	} else {
		panic("rhs is not PointK256")
	}
}

func (p *Point) ApplySub(q curves.Point, n *saferith.Nat) curves.Point {
	return p.Sub(q.Mul(NewScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *Point) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		value := k256impl.PointNew().Mul(p.V, r.V)
		return &Point{V: value}
	} else {
		panic("rhs is not ScalarK256")
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
	return p.V.GetY().Value[0]&1 == 1
}

func (*Point) IsSmallOrder() bool {
	return false
}

func (p *Point) IsTorsionElement(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.Mul(e).IsIdentity()
}

func (p *Point) ClearCofactor() curves.Point {
	return p.Clone()
}

// === Coordinates interface methods.

func (p *Point) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *Point) AffineX() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: p.V.GetX(),
	}
}

func (p *Point) AffineY() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: p.V.GetY(),
	}
}

func (p *Point) ProjectiveX() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: p.V.X,
	}
}

func (p *Point) ProjectiveY() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: p.V.Y,
	}
}

func (p *Point) ProjectiveZ() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: p.V.Z,
	}
}

// === Serialisation.

func (p *Point) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)

	t := k256impl.PointNew().ToAffine(p.V)

	x[0] |= t.Y.Bytes()[0] & 1

	xBytes := t.X.Bytes()
	copy(x[1:], bitstring.ReverseBytes(xBytes[:]))
	return x[:]
}

func (p *Point) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	t := k256impl.PointNew().ToAffine(p.V)
	arr := t.X.Bytes()
	copy(out[1:33], bitstring.ReverseBytes(arr[:]))
	arr = t.Y.Bytes()
	copy(out[33:], bitstring.ReverseBytes(arr[:]))
	return out[:]
}

func (*Point) FromAffineCompressed(input []byte) (curves.Point, error) {
	var raw [base.FieldBytes]byte
	if len(input) != 33 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	sign := int(input[0])
	if sign != 2 && sign != 3 {
		return nil, errs.NewFailed("invalid sign byte")
	}
	sign &= 0x1

	copy(raw[:], bitstring.ReverseBytes(input[1:]))
	x, err := fp.New().SetBytes(&raw)
	if err != nil {
		return nil, errs.WrapCoordinates(err, "x")
	}

	value := k256impl.PointNew().Identity()
	rhs := fp.New()
	value.Arithmetic.RhsEq(rhs, x)
	// test that rhs is quadratic residue
	// if not, then this Point is at infinity
	y, wasQr := fp.New().Sqrt(rhs)
	if wasQr {
		// fix the sign
		sigY := int(y.Bytes()[0] & 1)
		if sigY != sign {
			y.Neg(y)
		}
		value.X = x
		value.Y = y
		value.Z.SetOne()
	}
	return &Point{V: value}, nil
}

func (*Point) FromAffineUncompressed(input []byte) (curves.Point, error) {
	var arr [base.FieldBytes]byte
	if len(input) != 65 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	if input[0] != 4 {
		return nil, errs.NewFailed("invalid sign byte")
	}

	copy(arr[:], bitstring.ReverseBytes(input[1:33]))
	x, err := fp.New().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapCoordinates(err, "x")
	}
	copy(arr[:], bitstring.ReverseBytes(input[33:]))
	y, err := fp.New().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapCoordinates(err, "y")
	}
	value := k256impl.PointNew()
	value.X = x
	value.Y = y
	value.Z.SetOne()
	if !value.IsOnCurve() {
		return nil, errs.NewMembership("deserialised value is not on curve")
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
		return errs.NewType("name %s is not supported", name)
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewType("invalid point")
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
		return errs.NewType("name %s is not supported", name)
	}
	P, ok := pt.(*Point)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V = P.V
	return nil
}

// === Hashable.

func (p *Point) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}
