package k256

import (
	"encoding"
	"encoding/binary"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/mixins"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	k256impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fp"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ curves.Point = (*Point)(nil)
var _ curves.ProjectiveCurveCoordinates = (*Point)(nil)
var _ encoding.BinaryMarshaler = (*Point)(nil)
var _ encoding.BinaryUnmarshaler = (*Point)(nil)
var _ json.Unmarshaler = (*Point)(nil)

type Point struct {
	// mixins.Mixin_GroupElement[curves.Curve, curves.Point]
	mixins.Mixin_AdditiveGroupElement[curves.Curve, curves.Point]
	mixins.Mixin_CyclicGroupElement[curves.Curve, curves.Point]
	mixins.PointedSetElement[curves.Curve, curves.Point]
	// mixins.X[curves.Curve, curves.Point]
	// mixins.Y[curves.Curve, curves.Point]
	// mixins.AdditiveMonoidElement[curves.Curve, curves.Point]
	V *impl.EllipticPoint

	_ ds.Incomparable
}

// type P2 struct {
// 	mixins.Mixin_AdditiveGroupElement[curves.Curve, curves.Point]
// 	// mixins.AdditiveMonoidElement[curves.Curve, curves.Point]
// 	V *impl.EllipticPoint

// 	_ ds.Incomparable
// }

func NewPoint() *Point {
	// p := P2{}
	return NewCurve().AdditiveIdentity().(*Point)
}

// === Set Methods.

func (p *Point) Unwrap() curves.Point {
	return p
}

// func (p *Point) IsBasePoint() bool {
// 	return p
// }

func (p *Point) Structure() curves.Curve {
	return NewCurve()
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
		V: k256impl.PointNew().Set(p.V),
	}
}

func (p *Point) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}

// === Groupoid Methods.

// === Additive Groupoid Methods.

func (p *Point) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
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

func (p *Point) Double() curves.Point {
	value := k256impl.PointNew().Double(p.V)
	return &Point{V: value}
}

// === Monoid Methods.

// === Additive Monoid Methods.

// === Group Methods.

func (p *Point) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	if !p.Curve().IsDefinedUnder(under) {
		return nil, errs.NewArgument("invalid operator")
	}
	//TODO: figure out for general operator
	return p.AdditiveInverse(), nil

}

func (p *Point) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	output, err := under.Map(p, of.Unwrap())
	if err != nil {
		return false, errs.WrapFailed(err, "could not apply the given operator")
	}
	return output.IsIdentity(under)
}

func (p *Point) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	if !p.Curve().IsDefinedUnder(under) {
		return false, errs.NewArgument("invalid operator")
	}
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity(), nil
}

// === Subgroup Methods.

func (*Point) IsSmallOrder() bool {
	return false
}

func (p *Point) ClearCofactor() curves.Point {
	return p.Clone()
}

// === Additive Group Methods.

func (p *Point) AdditiveInverse() curves.Point {
	value := k256impl.PointNew().Neg(p.V)
	return &Point{V: value}
}

func (p *Point) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *Point) IsAdditiveTorsionElement(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (p *Point) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (p *Point) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
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

func (p *Point) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	if q == nil {
		panic("rhs is nil")
	}
	qq, ok := q.(*Point)
	if ok {
		return p.Add(qq.ScalarMul(NewScalarField().Element().SetNat(n)))
	} else {
		panic("rhs is not PointK256")
	}
}

// === Cyclic Group Methods.

func (p *Point) IsDesignatedGenerator() bool {
	return p.Equal(p.Curve().Generator())
}

// === Affine Algebraic Variety Element Methods.

func (p *Point) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

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

// === Affine Algebraic Point Methods.

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

// === Elliptic Point Methods

func (p *Point) IsInPrimeSubGroup() bool {
	return p.V.IsOnCurve()
}

func (p *Point) IsNegative() bool {
	return p.V.GetY().Value[0]&1 == 1
}

// === Vector Methods.

func (p *Point) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
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

// Prime Order SubGroup Methods.

func (*Point) Curve() curves.Curve {
	return NewCurve()
}

// === Coordinates interface methods.

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
