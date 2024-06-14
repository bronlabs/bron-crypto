package fourq

import (
	"encoding"
	"encoding/binary"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/fourq/impl"
	curvesImpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ curves.Point = (*Point)(nil)
var _ curves.ExtendedCoordinates = (*Point)(nil)
var _ encoding.BinaryMarshaler = (*Point)(nil)
var _ encoding.BinaryUnmarshaler = (*Point)(nil)
var _ json.Marshaler = (*Point)(nil)
var _ json.Unmarshaler = (*Point)(nil)

type Point struct {
	V *impl.ExtendedPoint

	_ ds.Incomparable
}

func NewPoint() *Point {
	return &Point{V: new(impl.ExtendedPoint).Identity()}
}

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

func (p *Point) IsInPrimeSubGroup() bool {
	return p.V.InCorrectSubgroup() == 1
}

func (*Point) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	panic("not implemented")
}

func (*Point) IsBasePoint() bool {
	//TODO implement me
	panic("implement me")
}

func (*Point) CanGenerateAllElements() bool {
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
		V: new(impl.ExtendedPoint).Set(p.V),
	}
}

// === Groupoid Methods.

func (p *Point) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *Point) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.ScalarMul(NewCurve().Scalar().SetNat(n))
}

func (*Point) Order(op algebra.BinaryOperator[curves.Point]) (*saferith.Modulus, error) {
	panic("implement me")
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
		panic("rhs in nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		return &Point{V: new(impl.ExtendedPoint).Add(p.V, r.V)}
	} else {
		panic("rhs in not point FourQ")
	}
}

func (p *Point) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewScalarField().Element().SetNat(n)))
}

func (p *Point) Double() curves.Point {
	return &Point{V: new(impl.ExtendedPoint).Add(p.V, p.V)}
}

func (p *Point) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*Point) IsIdentity(under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *Point) IsAdditiveIdentity() bool {
	return p.V.IsIdentity() == 1
}

// === Group Methods.

func (*Point) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

func (*Point) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Group Methods.

func (p *Point) AdditiveInverse() curves.Point {
	return &Point{V: new(impl.ExtendedPoint).Neg(p.V)}
}

func (p *Point) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *Point) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs in nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		rTmp := new(impl.ExtendedPoint).Neg(r.V)
		return &Point{V: rTmp.Add(p.V, rTmp)}
	} else {
		panic("rhs in not point FourQ")
	}
}

func (p *Point) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Sub(q.Unwrap().ScalarMul(NewScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *Point) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	if rhs == nil {
		panic("rhs in nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		rLimbs := r.V.Limbs()
		value := new(impl.ExtendedPoint).Mul(p.V, &rLimbs)
		return &Point{V: value}
	} else {
		panic("rhs in not scalar FourQ")
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
	return p.AffineY().Bytes()[0]&1 == 1
}

func (p *Point) ClearCofactor() curves.Point {
	return &Point{
		V: new(impl.ExtendedPoint).ClearCofactor(p.V),
	}
}

func (p *Point) IsSmallOrder() bool {
	return p.ClearCofactor().IsAdditiveIdentity()
}

func (*Point) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Coordinates.

func (p *Point) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *Point) AffineX() curves.BaseFieldElement {
	pAffine := new(impl.ExtendedPoint).ToAffine(p.V)
	return &BaseFieldElement{
		V: pAffine.GetX(),
	}
}

func (p *Point) AffineY() curves.BaseFieldElement {
	pAffine := new(impl.ExtendedPoint).ToAffine(p.V)
	return &BaseFieldElement{
		V: pAffine.GetY(),
	}
}

func (*Point) ExtendedX() curves.BaseFieldElement {
	panic("not implemented")
}

func (*Point) ExtendedY() curves.BaseFieldElement {
	panic("not implemented")
}

func (*Point) ExtendedZ() curves.BaseFieldElement {
	panic("not implemented")
}

func (*Point) ExtendedT() curves.BaseFieldElement {
	panic("not implemented")
}

// === Serialisation.

func (p *Point) ToAffineCompressed() []byte {
	data := p.V.ToCompressed()
	return data[:]
}

func (*Point) ToAffineUncompressed() []byte {
	panic("not implemented")
}

func (*Point) FromAffineCompressed(inBytes []byte) (curves.Point, error) {
	x, err := new(impl.ExtendedPoint).FromCompressed(inBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot deserialize point")
	}

	return &Point{V: x}, nil
}

func (*Point) FromAffineUncompressed(inBytes []byte) (curves.Point, error) {
	panic("not implemented")
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
	p.V = ppt.V
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
	pt, err := curvesImpl.UnmarshalJson(p.FromAffineCompressed, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	name, _, err := curvesImpl.ParseBinary(input)
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
