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

// var _ curves.PairingPoint = (*TritonPoint)(nil).
var _ curves.ProjectiveCurveCoordinates = (*TritonPoint)(nil)
var _ encoding.BinaryMarshaler = (*TritonPoint)(nil)
var _ encoding.BinaryUnmarshaler = (*TritonPoint)(nil)
var _ json.Unmarshaler = (*TritonPoint)(nil)

type TritonPoint struct {
	V impl.TritonPoint

	_ ds.Incomparable
}

func NewTritonPoint() *TritonPoint {
	return NewTriton().Element().(*TritonPoint)
}

// === Basic Methods.

func (*TritonPoint) Structure() curves.Curve {
	return NewTriton()
}

func (p *TritonPoint) Unwrap() curves.Point {
	return p
}

func (*TritonPoint) ApplyOp(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (p *TritonPoint) IsInPrimeSubGroup() bool {
	return p.V.InCorrectSubgroup() == 1
}

func (p *TritonPoint) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (*TritonPoint) IsBasePoint() bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonPoint) CanGenerateAllElements() bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonPoint) IsDesignatedGenerator() bool {
	//TODO implement me
	panic("implement me")
}

func (p *TritonPoint) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*TritonPoint)
	if ok {
		return p.V.Equal(&r.V) == 1
	} else {
		return false
	}
}

func (p *TritonPoint) Clone() curves.Point {
	return &TritonPoint{V: *new(impl.TritonPoint).Set(&p.V)}
}

// === Groupoid Methods.

func (p *TritonPoint) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *TritonPoint) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.ScalarMul(NewTriton().Scalar().SetNat(n))
}

func (*TritonPoint) Order(op algebra.BinaryOperator[curves.Point]) (*saferith.Modulus, error) {
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

func (p *TritonPoint) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*TritonPoint)
	if ok {
		return &TritonPoint{V: *new(impl.TritonPoint).Add(&p.V, &r.V)}
	} else {
		panic("rhs is not Triton point")
	}
}

func (p *TritonPoint) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewTritonScalarField().Element().SetNat(n)))
}

func (p *TritonPoint) Double() curves.Point {
	return &TritonPoint{V: *new(impl.TritonPoint).Double(&p.V)}
}

func (p *TritonPoint) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*TritonPoint) IsIdentity(under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *TritonPoint) IsAdditiveIdentity() bool {
	return p.V.IsIdentity() == 1
}

// === Group Methods.

func (*TritonPoint) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

func (*TritonPoint) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Group Methods.

func (p *TritonPoint) AdditiveInverse() curves.Point {
	return &TritonPoint{V: *new(impl.TritonPoint).Neg(&p.V)}
}

func (p *TritonPoint) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *TritonPoint) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*TritonPoint)
	if ok {
		return &TritonPoint{V: *new(impl.TritonPoint).Sub(&p.V, &r.V)}
	} else {
		panic("rhs is not Triton point")
	}
}

func (p *TritonPoint) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Sub(q.Unwrap().ScalarMul(NewTritonScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *TritonPoint) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PlutoTritonScalar)
	if ok {
		return &TritonPoint{V: *new(impl.TritonPoint).Mul(&p.V, &r.V)}
	} else {
		panic("rhs is not Pluto/Triton scalar")
	}
}

// === Curve Methods.

func (*TritonPoint) Curve() curves.Curve {
	return NewTriton()
}

func (p *TritonPoint) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (p *TritonPoint) IsNegative() bool {
	// According to https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
	// This bit represents the sign of the `y` coordinate which is what we want
	return (p.V.ToCompressed()[0]>>5)&1 == 1
}

func (p *TritonPoint) IsSmallOrder() bool {
	return p.ClearCofactor().IsAdditiveIdentity()
}

func (p *TritonPoint) ClearCofactor() curves.Point {
	return &TritonPoint{V: *new(impl.TritonPoint).ClearCofactor(&p.V)}
}

// === Pairing Methods.

//func (*TritonPoint) PairingCurve() curves.PairingCurve {
//	return NewPairingCurve()
//}
//
//func (*TritonPoint) OtherPrimeAlgebraicSubGroup() curves.Curve {
//	return NewG1()
//}.

func (*TritonPoint) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

//func (p *TritonPoint) Pair(rhs curves.PairingPoint) curves.GtMember {
//	pt, ok := rhs.(*)
//	if !ok {
//		panic("rhs is not in G1")
//	}
//	e := new(bls12381impl.Engine)
//	e.AddPair(pt.V, p.V)
//
//	value := e.Result()
//
//	return &GtMember{V: value}
//}.

// === Coordinate Interface Methods.

func (p *TritonPoint) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *TritonPoint) AffineX() curves.BaseFieldElement {
	return &TritonBaseFieldElement{
		V: *p.V.GetX(),
	}
}

func (p *TritonPoint) AffineY() curves.BaseFieldElement {
	return &TritonBaseFieldElement{
		V: *p.V.GetY(),
	}
}

func (p *TritonPoint) ProjectiveX() curves.BaseFieldElement {
	return &TritonBaseFieldElement{
		V: p.V.X,
	}
}

func (p *TritonPoint) ProjectiveY() curves.BaseFieldElement {
	return &TritonBaseFieldElement{
		V: p.V.Y,
	}
}

func (p *TritonPoint) ProjectiveZ() curves.BaseFieldElement {
	return &TritonBaseFieldElement{
		V: p.V.Z,
	}
}

// === Serialisation.

func (p *TritonPoint) ToAffineCompressed() []byte {
	out := p.V.ToCompressed()
	return out[:]
}

func (p *TritonPoint) ToAffineUncompressed() []byte {
	out := p.V.ToUncompressed()
	return out[:]
}

func (*TritonPoint) FromAffineCompressed(input []byte) (curves.Point, error) {
	var b [impl.WideFieldBytes]byte
	copy(b[:], input)
	value, err := new(impl.TritonPoint).FromCompressed(&b)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't construct Triton point from affine compressed")
	}
	return &TritonPoint{V: *value}, nil
}

func (*TritonPoint) FromAffineUncompressed(input []byte) (curves.Point, error) {
	var b [impl.WideFieldBytesFp2]byte
	copy(b[:], input)
	value, err := new(impl.TritonPoint).FromUncompressed(&b)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't construct Triton point from affine uncompressed")
	}
	return &TritonPoint{V: *value}, nil
}

func (p *TritonPoint) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *TritonPoint) UnmarshalBinary(input []byte) error {
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
	ppt, ok := pt.(*TritonPoint)
	if !ok {
		return errs.NewType("invalid point")
	}
	p.V = ppt.V
	return nil
}

func (p *TritonPoint) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *TritonPoint) UnmarshalJSON(input []byte) error {
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
	P, ok := pt.(*TritonPoint)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V = P.V
	return nil
}

func (p *TritonPoint) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}
