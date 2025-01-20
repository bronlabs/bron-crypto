package k256

import (
	"encoding"
	"encoding/binary"
	"encoding/json"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	curvesImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl"
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
	k256Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/k256/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

var _ curves.Point = (*Point)(nil)
var _ curves.ProjectiveCurveCoordinates = (*Point)(nil)
var _ encoding.BinaryMarshaler = (*Point)(nil)
var _ encoding.BinaryUnmarshaler = (*Point)(nil)
var _ json.Unmarshaler = (*Point)(nil)

type Point struct {
	V k256Impl.Point

	_ ds.Incomparable
}

func NewPoint() *Point {
	return NewCurve().AdditiveIdentity().(*Point)
}

// === Basic Methods.

func (*Point) Structure() curves.Curve {
	return NewCurve()
}

func (p *Point) Unwrap() curves.Point {
	return p
}

func (*Point) ApplyOp(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Point) IsInPrimeSubGroup() bool {
	return true
}

func (p *Point) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (p *Point) IsBasePoint() bool {
	return NewCurve().Generator().Equal(p)
}

func (p *Point) CanGenerateAllElements() bool {
	return p.IsInPrimeSubGroup()
}

func (p *Point) IsDesignatedGenerator() bool {
	return p.IsBasePoint()
}

func (p *Point) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*Point)
	if !ok {
		return false
	}

	return p.V.Equals(&r.V) == 1
}

func (p *Point) Clone() curves.Point {
	clone := new(Point)
	clone.V.Set(&p.V)
	return clone
}

// === Groupoid Methods.

func (p *Point) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *Point) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.Unwrap().ScalarMul(NewCurve().Scalar().SetNat(n))
}

func (*Point) Order(op algebra.BinaryOperator[curves.Point]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
	//if p.IsIdentity() {
	//	return saferith.ModulusFromUint64(0), nil
	//}
	//q := p.Clone()
	//order := saferithUtils.NatOne
	//for !q.IsIdentity() {
	//	q = q.Add(p)
	//	saferithUtils.NatInc(order)
	//}
	//return saferith.ModulusFromNat(order), nil
}

// === Additive Groupoid Methods.

func (p *Point) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if !ok {
		panic("rhs is not PointK256")
	}

	value := new(Point)
	value.V.Add(&p.V, &r.V)
	return value
}

func (p *Point) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewScalarField().Element().SetNat(n)))
}

func (p *Point) Double() curves.Point {
	value := new(Point)
	value.V.Double(&p.V)
	return value
}

func (p *Point) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*Point) IsIdentity(under algebra.BinaryOperator[curves.Point]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *Point) IsAdditiveIdentity() bool {
	return p.V.IsIdentity() == 1
}

// === Group Methods.

func (*Point) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Point) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

// === Additive Group Methods.

func (p *Point) AdditiveInverse() curves.Point {
	neg := new(Point)
	neg.V.Neg(&p.V)
	return neg
}

func (p *Point) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *Point) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if !ok {
		panic("rhs is not PointK256")
	}

	value := new(Point)
	value.V.Sub(&p.V, &r.V)
	return value
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
	if !ok {
		panic("rhs is not ScalarK256")
	}

	value := new(Point)
	pointsImpl.ScalarMulLimbs[*k256Impl.Fp](&value.V, &p.V, r.V.Limbs())
	return value
}

// === Curve Methods.

func (*Point) Curve() curves.Curve {
	return NewCurve()
}

func (p *Point) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (p *Point) IsNegative() bool {
	var x, y k256Impl.Fp
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		return false
	}

	return y.Bytes()[0]&0b1 == 1
}

func (*Point) IsSmallOrder() bool {
	return false
}

func (*Point) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (p *Point) ClearCofactor() curves.Point {
	return p.Clone()
}

// === Coordinates interface methods.

func (p *Point) AffineCoordinates() []curves.BaseFieldElement {
	x := new(BaseFieldElement)
	y := new(BaseFieldElement)
	ok := p.V.ToAffine(&x.V, &y.V)
	if ok != 1 {
		return []curves.BaseFieldElement{
			p.Curve().BaseField().AdditiveIdentity(),
			p.Curve().BaseField().AdditiveIdentity(),
		}
	}

	return []curves.BaseFieldElement{x, y}
}

func (p *Point) AffineX() curves.BaseFieldElement {
	return p.AffineCoordinates()[0]
}

func (p *Point) AffineY() curves.BaseFieldElement {
	return p.AffineCoordinates()[1]
}

func (p *Point) ProjectiveX() curves.BaseFieldElement {
	x := new(BaseFieldElement)
	x.V.Set(&p.V.X)
	return x
}

func (p *Point) ProjectiveY() curves.BaseFieldElement {
	y := new(BaseFieldElement)
	y.V.Set(&p.V.Y)
	return y
}

func (p *Point) ProjectiveZ() curves.BaseFieldElement {
	z := new(BaseFieldElement)
	z.V.Set(&p.V.Z)
	return z
}

// === Serialisation.

func (p *Point) ToAffineCompressed() []byte {
	var compressedBytes [33]byte
	compressedBytes[0] = byte(2)
	if p.IsAdditiveIdentity() {
		return compressedBytes[:]
	}

	var px, py k256Impl.Fp
	ok := p.V.ToAffine(&px, &py)
	if ok != 1 {
		panic("this should never happen")
	}

	compressedBytes[0] |= py.Bytes()[0] & 1
	pxBytes := px.Bytes()
	slices.Reverse(pxBytes)
	copy(compressedBytes[1:], pxBytes)
	return compressedBytes[:]
}

func (p *Point) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	if p.IsAdditiveIdentity() {
		return out[:]
	}

	var px, py k256Impl.Fp
	ok := p.V.ToAffine(&px, &py)
	if ok != 1 {
		panic("this should never happen")
	}

	pxBytes := px.Bytes()
	slices.Reverse(pxBytes)
	copy(out[1:33], pxBytes)

	pyBytes := py.Bytes()
	slices.Reverse(pyBytes)
	copy(out[33:], pyBytes)

	return out[:]
}

func (p *Point) FromAffineCompressed(input []byte) (curves.Point, error) {
	if len(input) != 33 {
		return nil, errs.NewLength("invalid byte sequence")
	}

	sign := input[0]
	if sign != 2 && sign != 3 {
		return nil, errs.NewFailed("invalid sign byte")
	}
	sign &= 0x1

	var xBytes [k256Impl.FpBytes]byte
	copy(xBytes[:], input[1:])
	slices.Reverse(xBytes[:])

	var x, y k256Impl.Fp
	ok := x.SetBytes(xBytes[:])
	if ok != 1 {
		return nil, errs.NewCoordinates("x")
	}
	if x.IsZero() == 1 {
		return p.Curve().AdditiveIdentity(), nil
	}

	result := new(Point)
	ok = result.V.SetFromAffineX(&x)
	if ok != 1 {
		return nil, errs.NewCoordinates("x")
	}
	ok = result.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}

	ySign := result.V.Y.Bytes()[0] & 0b1
	if sign != ySign {
		result.V.Neg(&result.V)
	}

	return result, nil
}

func (p *Point) FromAffineUncompressed(input []byte) (curves.Point, error) {
	if len(input) != 65 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	if input[0] != 4 {
		return nil, errs.NewFailed("invalid sign byte")
	}

	var xBytes, yBytes [32]byte
	copy(xBytes[:], input[1:33])
	copy(yBytes[:], input[33:])
	slices.Reverse(xBytes[:])
	slices.Reverse(yBytes[:])

	var x, y k256Impl.Fp
	okx := x.SetBytes(xBytes[:])
	if okx != 1 {
		return nil, errs.NewCoordinates("x")
	}
	oky := y.SetBytes(yBytes[:])
	if oky != 1 {
		return nil, errs.NewCoordinates("y")
	}
	if x.IsZero() == 1 && y.IsZero() == 1 {
		return p.Curve().AdditiveIdentity(), nil
	}

	result := new(Point)
	ok := result.V.SetAffine(&x, &y)
	if ok != 1 {
		return nil, errs.NewCoordinates("x/y")
	}

	return result, nil
}

func (p *Point) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *Point) UnmarshalBinary(input []byte) error {
	pt, err := curvesImpl.UnmarshalBinary(p.FromAffineCompressed, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal binary")
	}
	name, _, err := curvesImpl.ParseBinary(input)
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
	p.V.Set(&ppt.V)
	return nil
}

func (p *Point) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *Point) UnmarshalJSON(input []byte) error {
	pt, err := curvesImpl.UnmarshalJson(p.Curve().Name(), p.FromAffineCompressed, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	P, ok := pt.(*Point)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V.Set(&P.V)
	return nil
}

// === Hashable.

func (p *Point) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}
