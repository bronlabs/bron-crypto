package p256

import (
	"encoding"
	"encoding/binary"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb4"
	p256impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fp"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ curves.Point = (*Point)(nil)
var _ curves.ProjectiveCurveCoordinates = (*Point)(nil)
var _ encoding.BinaryMarshaler = (*Point)(nil)
var _ encoding.BinaryUnmarshaler = (*Point)(nil)
var _ json.Unmarshaler = (*Point)(nil)

type Point struct {
	V *limb4.EllipticPoint

	_ ds.Incomparable
}

func (*Point) IsInvolution(under algebra.Operator) (bool, error) {
	panic("implement me")
}
func (*Point) IsInvolutionUnderAddition() bool {
	panic("implement me")
}
func (p *Point) CanGenerateAllElements(under algebra.Operator) bool {
	return p.IsInPrimeSubGroup()
}

func NewPoint() *Point {
	return NewCurve().AdditiveIdentity().(*Point)
}

func (*Point) Structure() curves.Curve {
	return NewCurve()
}

func (p *Point) Unwrap() curves.Point {
	return p
}

func (*Point) Apply(operator algebra.Operator, x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (p *Point) IsInPrimeSubGroup() bool {
	return p.V.IsOnCurve() || p.IsAdditiveIdentity()
}

func (p *Point) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (*Point) IsBasePoint() bool {
	//TODO implement me
	panic("implement me")
}

func (*Point) IsDesignatedGenerator() bool {
	//TODO implement me
	panic("implement me")
}

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
		V: p256impl.PointNew().Set(p.V),
	}
}

// === Groupoid Methods.

func (*Point) Operate(op algebra.Operator, rhs algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	panic("not implemented")
}

func (p *Point) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.ScalarMul(NewCurve().Scalar().SetNat(n))
}

func (*Point) Order(op algebra.Operator) (*saferith.Nat, error) {
	panic("not implemented")
	//if p.IsIdentity() {
	//	return saferith.ModulusFromUint64(0)
	//}
	//q := p.Clone()
	//order := saferithUtils.NatOne
	//for !q.IsIdentity() {
	//	q = q.Add(p)
	//	saferithUtils.NatInc(order)
	//}
	//return saferith.ModulusFromNat(order)
}

// === Additive Groupoid Methods.

func (p *Point) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		value := p256impl.PointNew().Add(p.V, r.V)
		return &Point{V: value}
	} else {
		panic("rhs is not PointP256")
	}
}

func (p *Point) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewScalarField().Element().SetNat(n)))
}

func (p *Point) Double() curves.Point {
	value := p256impl.PointNew().Double(p.V)
	return &Point{V: value}
}

func (p *Point) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*Point) IsIdentity(under algebra.Operator) (bool, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *Point) IsAdditiveIdentity() bool {
	return p.V.IsIdentity()
}

// === Group Methods.

func (*Point) Inverse(under algebra.Operator) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Point) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.Operator) (bool, error) {
	//TODO implement me
	panic("implement me")
}

// === Additive Group Methods.

func (p *Point) AdditiveInverse() curves.Point {
	value := p256impl.PointNew().Neg(p.V)
	return &Point{V: value}
}

func (p *Point) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *Point) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		value := p256impl.PointNew().Sub(p.V, r.V)
		return &Point{V: value}
	} else {
		panic("rhs is not PointP256")
	}
}

func (p *Point) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Sub(q.Unwrap().ScalarMul(NewScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *Point) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		value := p256impl.PointNew().Mul(p.V, r.V)
		return &Point{V: value}
	} else {
		panic("rhs is not ScalarP256")
	}
}

// === Curve Methods.

func (*Point) Curve() curves.Curve {
	return NewCurve()
}

func (p *Point) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (p *Point) IsNegative() bool {
	return p.V.GetY().Value[0]&1 == 1
}

func (*Point) IsSmallOrder() bool {
	return false
}

func (*Point) IsTorsionElement(order *saferith.Modulus, under algebra.Operator) (bool, error) {
	//TODO implement me
	panic("implement me")
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

	t := p256impl.PointNew().ToAffine(p.V)

	x[0] |= t.Y.Bytes()[0] & 1

	xBytes := t.X.Bytes()
	copy(x[1:], bitstring.ReverseBytes(xBytes[:]))
	return x[:]
}

func (p *Point) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	t := p256impl.PointNew().ToAffine(p.V)
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
		return nil, errs.NewSerialisation("invalid sign byte")
	}
	sign &= 0x1

	copy(raw[:], bitstring.ReverseBytes(input[1:]))
	x, err := fp.New().SetBytes(&raw)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "set bytes failed")
	}

	value := p256impl.PointNew().Identity()
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
		return nil, errs.NewSerialisation("invalid sign byte")
	}

	copy(arr[:], bitstring.ReverseBytes(input[1:33]))
	x, err := fp.New().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapCoordinates(err, "set bytes failed")
	}
	copy(arr[:], bitstring.ReverseBytes(input[33:]))
	y, err := fp.New().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapCoordinates(err, "set bytes failed")
	}
	value := p256impl.PointNew()
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
