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
	_ curves.ProjectiveCurveCoordinates = (*ErisPoint)(nil)
	_ encoding.BinaryMarshaler          = (*ErisPoint)(nil)
	_ encoding.BinaryUnmarshaler        = (*ErisPoint)(nil)
	_ json.Unmarshaler                  = (*ErisPoint)(nil)
)

type ErisPoint struct {
	V impl.ErisPoint

	_ ds.Incomparable
}

func NewErisPoint() *ErisPoint {
	return NewEris().Element().(*ErisPoint)
}

// === Basic Methods.

func (*ErisPoint) Structure() curves.Curve {
	return NewEris()
}

func (p *ErisPoint) Unwrap() curves.Point {
	return p
}

func (*ErisPoint) ApplyOp(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (p *ErisPoint) IsInPrimeSubGroup() bool {
	return p.V.InCorrectSubgroup() == 1
}

func (p *ErisPoint) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (*ErisPoint) IsBasePoint() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisPoint) CanGenerateAllElements() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisPoint) IsDesignatedGenerator() bool {
	//TODO implement me
	panic("implement me")
}

func (p *ErisPoint) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*ErisPoint)
	if ok {
		return p.V.Equal(&r.V) == 1
	} else {
		return false
	}
}

func (p *ErisPoint) Clone() curves.Point {
	return &ErisPoint{V: *new(impl.ErisPoint).Set(&p.V)}
}

// === Groupoid Methods.

func (p *ErisPoint) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *ErisPoint) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.ScalarMul(NewEris().Scalar().SetNat(n))
}

func (*ErisPoint) Order(op algebra.BinaryOperator[curves.Point]) (*saferith.Modulus, error) {
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

func (p *ErisPoint) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ErisPoint)
	if ok {
		return &ErisPoint{V: *new(impl.ErisPoint).Add(&p.V, &r.V)}
	} else {
		panic("rhs is not Eris point")
	}
}

func (p *ErisPoint) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewErisScalarField().Element().SetNat(n)))
}

func (p *ErisPoint) Double() curves.Point {
	return &ErisPoint{V: *new(impl.ErisPoint).Double(&p.V)}
}

func (p *ErisPoint) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*ErisPoint) IsIdentity(under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *ErisPoint) IsAdditiveIdentity() bool {
	return p.V.IsIdentity() == 1
}

// === Group Methods.

func (*ErisPoint) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

func (*ErisPoint) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Group Methods.

func (p *ErisPoint) AdditiveInverse() curves.Point {
	return &ErisPoint{V: *new(impl.ErisPoint).Neg(&p.V)}
}

func (p *ErisPoint) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *ErisPoint) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ErisPoint)
	if ok {
		return &ErisPoint{V: *new(impl.ErisPoint).Sub(&p.V, &r.V)}
	} else {
		panic("rhs is not Eris point")
	}
}

func (p *ErisPoint) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Sub(q.Unwrap().ScalarMul(NewErisScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *ErisPoint) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ErisScalar)
	if ok {
		return &ErisPoint{V: *new(impl.ErisPoint).Mul(&p.V, &r.V)}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

// === Curve Methods.

func (*ErisPoint) Curve() curves.Curve {
	return NewEris()
}

func (p *ErisPoint) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (p *ErisPoint) IsNegative() bool {
	// According to https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
	// This bit represents the sign of the `y` coordinate which is what we want
	return (p.V.ToCompressed()[0]>>5)&1 == 1
}

func (p *ErisPoint) IsSmallOrder() bool {
	return p.ClearCofactor().IsAdditiveIdentity()
}

func (p *ErisPoint) ClearCofactor() curves.Point {
	return &ErisPoint{V: *new(impl.ErisPoint).ClearCofactor(&p.V)}
}

func (*ErisPoint) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
	//if order.Nat().Eq(p.Curve().SubGroupOrder().Nat()) == 1 {
	//	return p.V.InCorrectSubgroup() == 1
	//}
	//e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	//return p.Mul(e).IsIdentity()
}

// === Coordinate Interface Methods.

func (p *ErisPoint) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *ErisPoint) AffineX() curves.BaseFieldElement {
	return &ErisBaseFieldElement{
		V: *p.V.GetX(),
	}
}

func (p *ErisPoint) AffineY() curves.BaseFieldElement {
	return &ErisBaseFieldElement{
		V: *p.V.GetY(),
	}
}

func (p *ErisPoint) ProjectiveX() curves.BaseFieldElement {
	return &ErisBaseFieldElement{
		V: p.V.X,
	}
}

func (p *ErisPoint) ProjectiveY() curves.BaseFieldElement {
	return &ErisBaseFieldElement{
		V: p.V.Y,
	}
}

func (p *ErisPoint) ProjectiveZ() curves.BaseFieldElement {
	return &ErisBaseFieldElement{
		V: p.V.Z,
	}
}

// === Serialisation.

func (p *ErisPoint) ToAffineCompressed() []byte {
	out := p.V.ToCompressed()
	return out[:]
}

func (p *ErisPoint) ToAffineUncompressed() []byte {
	out := p.V.ToUncompressed()
	return out[:]
}

func (*ErisPoint) FromAffineCompressed(input []byte) (curves.Point, error) {
	var b [impl.FieldBytes]byte
	copy(b[:], input)
	value, err := new(impl.ErisPoint).FromCompressed(&b)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't construct G1 point from affine compressed")
	}
	return &ErisPoint{V: *value}, nil
}

func (*ErisPoint) FromAffineUncompressed(input []byte) (curves.Point, error) {
	var b [2 * impl.FieldBytes]byte
	copy(b[:], input)
	value, err := new(impl.ErisPoint).FromUncompressed(&b)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't construct G1 point from affine uncompressed")
	}
	return &ErisPoint{V: *value}, nil
}

func (p *ErisPoint) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *ErisPoint) UnmarshalBinary(input []byte) error {
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
	ppt, ok := pt.(*ErisPoint)
	if !ok {
		return errs.NewType("invalid point")
	}
	p.V = ppt.V
	return nil
}

func (p *ErisPoint) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *ErisPoint) UnmarshalJSON(input []byte) error {
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
	P, ok := pt.(*ErisPoint)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V = P.V
	return nil
}

// === Hashable.

func (p *ErisPoint) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}
