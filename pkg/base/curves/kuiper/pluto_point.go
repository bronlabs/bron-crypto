package kuiper

import (
	"encoding"
	"encoding/binary"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	curvesImpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var (
	//_ curves.PairingPoint = (*PlutoPoint)(nil).
	_ curves.ProjectiveCurveCoordinates = (*PlutoPoint)(nil)
	_ encoding.BinaryMarshaler          = (*PlutoPoint)(nil)
	_ encoding.BinaryUnmarshaler        = (*PlutoPoint)(nil)
	_ json.Unmarshaler                  = (*PlutoPoint)(nil)
)

type PlutoPoint struct {
	V impl.PlutoPoint

	_ ds.Incomparable
}

func NewPlutoPoint() *PlutoPoint {
	return NewPluto().AdditiveIdentity().(*PlutoPoint)
}

// === Basic Methods.

func (*PlutoPoint) Structure() curves.Curve {
	return NewPluto()
}

func (p *PlutoPoint) Unwrap() curves.Point {
	return p
}

func (*PlutoPoint) ApplyOp(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (p *PlutoPoint) IsInPrimeSubGroup() bool {
	return p.V.InCorrectSubgroup() == 1
}

func (p *PlutoPoint) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (*PlutoPoint) IsBasePoint() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoPoint) CanGenerateAllElements() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoPoint) IsDesignatedGenerator() bool {
	//TODO implement me
	panic("implement me")
}

func (p *PlutoPoint) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*PlutoPoint)
	if ok {
		return p.V.Equal(&r.V) == 1
	} else {
		return false
	}
}

func (p *PlutoPoint) Clone() curves.Point {
	return &PlutoPoint{V: *new(impl.PlutoPoint).Set(&p.V)}
}

// === Groupoid Methods.

func (p *PlutoPoint) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *PlutoPoint) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.ScalarMul(NewPluto().Scalar().SetNat(n))
}

func (*PlutoPoint) Order(op algebra.BinaryOperator[curves.Point]) (*saferith.Modulus, error) {
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

func (p *PlutoPoint) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PlutoPoint)
	if ok {
		return &PlutoPoint{V: *new(impl.PlutoPoint).Add(&p.V, &r.V)}
	} else {
		panic("rhs is not Pluto point")
	}
}

func (p *PlutoPoint) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewPlutoScalarField().Element().SetNat(n)))
}

func (p *PlutoPoint) Double() curves.Point {
	return &PlutoPoint{V: *new(impl.PlutoPoint).Double(&p.V)}
}

func (p *PlutoPoint) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*PlutoPoint) IsIdentity(under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *PlutoPoint) IsAdditiveIdentity() bool {
	return p.V.IsIdentity() == 1
}

// === Group Methods.

func (*PlutoPoint) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

func (*PlutoPoint) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Group Methods.

func (p *PlutoPoint) AdditiveInverse() curves.Point {
	return &PlutoPoint{V: *new(impl.PlutoPoint).Neg(&p.V)}
}

func (p *PlutoPoint) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *PlutoPoint) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PlutoPoint)
	if ok {
		return &PlutoPoint{V: *new(impl.PlutoPoint).Sub(&p.V, &r.V)}
	} else {
		panic("rhs is not Pluto point")
	}
}

func (p *PlutoPoint) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Sub(q.Unwrap().ScalarMul(NewPlutoScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *PlutoPoint) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PlutoTritonScalar)
	if ok {
		return &PlutoPoint{V: *new(impl.PlutoPoint).Mul(&p.V, &r.V)}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

// === Curve Methods.

func (*PlutoPoint) Curve() curves.Curve {
	return NewPluto()
}

func (p *PlutoPoint) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (p *PlutoPoint) IsNegative() bool {
	// According to https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
	// This bit represents the sign of the `y` coordinate which is what we want
	return (p.V.ToCompressed()[0]>>5)&1 == 1
}

func (p *PlutoPoint) IsSmallOrder() bool {
	return p.ClearCofactor().IsAdditiveIdentity()
}

func (p *PlutoPoint) ClearCofactor() curves.Point {
	return &PlutoPoint{V: *new(impl.PlutoPoint).ClearCofactor(&p.V)}
}

// === Pairing Methods.

//func (*PlutoPoint) PairingCurve() curves.PairingCurve {
//	return NewPairingCurve()
//}
//
//func (*PlutoPoint) OtherPrimeAlgebraicSubGroup() curves.Curve {
//	return NewG2()
//}.

func (*PlutoPoint) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
	//if order.Nat().Eq(p.Curve().SubGroupOrder().Nat()) == 1 {
	//	return p.V.InCorrectSubgroup() == 1
	//}
	//e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	//return p.Mul(e).IsIdentity()
}

//func (p *PlutoPoint) Pair(rhs curves.PairingPoint) curves.GtMember {
//	e := new(bls12381impl.Engine)
//	e.AddPair(p.V, rhs.(*PointG2).V)
//
//	value := e.Result()
//
//	return &GtMember{V: value}
//}.

// === Coordinate Interface Methods.

func (p *PlutoPoint) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *PlutoPoint) AffineX() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: *p.V.GetX(),
	}
}

func (p *PlutoPoint) AffineY() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: *p.V.GetY(),
	}
}

func (p *PlutoPoint) ProjectiveX() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: p.V.X,
	}
}

func (p *PlutoPoint) ProjectiveY() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: p.V.Y,
	}
}

func (p *PlutoPoint) ProjectiveZ() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: p.V.Z,
	}
}

// === Serialisation.

func (p *PlutoPoint) ToAffineCompressed() []byte {
	out := p.V.ToCompressed()
	return out[:]
}

func (p *PlutoPoint) ToAffineUncompressed() []byte {
	out := p.V.ToUncompressed()
	return out[:]
}

func (*PlutoPoint) FromAffineCompressed(input []byte) (curves.Point, error) {
	var b [impl.FieldBytes]byte
	copy(b[:], input)
	value, err := new(impl.PlutoPoint).FromCompressed(&b)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't construct G1 point from affine compressed")
	}
	return &PlutoPoint{V: *value}, nil
}

func (*PlutoPoint) FromAffineUncompressed(input []byte) (curves.Point, error) {
	var b [2 * impl.FieldBytes]byte
	copy(b[:], input)
	value, err := new(impl.PlutoPoint).FromUncompressed(&b)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't construct G1 point from affine uncompressed")
	}
	return &PlutoPoint{V: *value}, nil
}

func (p *PlutoPoint) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *PlutoPoint) UnmarshalBinary(input []byte) error {
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
	ppt, ok := pt.(*PlutoPoint)
	if !ok {
		return errs.NewType("invalid point")
	}
	p.V = ppt.V
	return nil
}

func (p *PlutoPoint) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *PlutoPoint) UnmarshalJSON(input []byte) error {
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
	P, ok := pt.(*PlutoPoint)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V = P.V
	return nil
}

// === Hashable.

func (p *PlutoPoint) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}
