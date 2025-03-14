package bls12381

import (
	"encoding"
	"encoding/binary"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	bls12381impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var _ curves.PairingPoint = (*PointG1)(nil)
var _ curves.ProjectiveCurveCoordinates = (*PointG1)(nil)
var _ encoding.BinaryMarshaler = (*PointG1)(nil)
var _ encoding.BinaryUnmarshaler = (*PointG1)(nil)
var _ json.Unmarshaler = (*PointG1)(nil)

type PointG1 struct {
	V *bls12381impl.G1

	_ ds.Incomparable
}

func NewPointG1() *PointG1 {
	return NewG1().AdditiveIdentity().(*PointG1)
}

// === Basic Methods.

func (*PointG1) Structure() curves.Curve {
	return NewG1()
}

func (p *PointG1) Unwrap() curves.Point {
	return p
}

func (*PointG1) ApplyOp(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (p *PointG1) IsInPrimeSubGroup() bool {
	return p.V.InCorrectSubgroup() == 1
}

func (p *PointG1) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (*PointG1) IsBasePoint() bool {
	//TODO implement me
	panic("implement me")
}

func (*PointG1) CanGenerateAllElements() bool {
	//TODO implement me
	panic("implement me")
}

func (*PointG1) IsDesignatedGenerator() bool {
	//TODO implement me
	panic("implement me")
}

func (p *PointG1) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*PointG1)
	if ok {
		return p.V.Equal(r.V) == 1
	} else {
		return false
	}
}

func (p *PointG1) Clone() curves.Point {
	return &PointG1{V: new(bls12381impl.G1).Set(p.V)}
}

// === Groupoid Methods.

func (p *PointG1) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *PointG1) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.ScalarMul(NewG1().Scalar().SetNat(n))
}

func (*PointG1) Order(op algebra.BinaryOperator[curves.Point]) (*saferith.Modulus, error) {
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

func (p *PointG1) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG1)
	if ok {
		return &PointG1{V: new(bls12381impl.G1).Add(p.V, r.V)}
	} else {
		panic("rhs is not PointBls12381G1")
	}
}

func (p *PointG1) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewScalarFieldG1().Element().SetNat(n)))
}

func (p *PointG1) Double() curves.Point {
	return &PointG1{V: new(bls12381impl.G1).Double(p.V)}
}

func (p *PointG1) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*PointG1) IsIdentity(under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *PointG1) IsAdditiveIdentity() bool {
	return p.V.IsIdentity() == 1
}

// === Group Methods.

func (*PointG1) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

func (*PointG1) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Group Methods.

func (p *PointG1) AdditiveInverse() curves.Point {
	return &PointG1{V: new(bls12381impl.G1).Neg(p.V)}
}

func (p *PointG1) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *PointG1) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG1)
	if ok {
		return &PointG1{V: new(bls12381impl.G1).Sub(p.V, r.V)}
	} else {
		panic("rhs is not PointBls12381G1")
	}
}

func (p *PointG1) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Sub(q.Unwrap().ScalarMul(NewScalarFieldG1().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *PointG1) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		return &PointG1{V: new(bls12381impl.G1).Mul(p.V, r.V)}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

// === Curve Methods.

func (*PointG1) Curve() curves.Curve {
	return NewG1()
}

func (p *PointG1) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (p *PointG1) IsNegative() bool {
	// According to https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
	// This bit represents the sign of the `y` coordinate which is what we want
	return (p.V.ToCompressed()[0]>>5)&1 == 1
}

func (p *PointG1) IsSmallOrder() bool {
	return p.ClearCofactor().IsAdditiveIdentity()
}

func (p *PointG1) ClearCofactor() curves.Point {
	return &PointG1{V: new(bls12381impl.G1).ClearCofactor(p.V)}
}

// === Pairing Methods.

func (*PointG1) PairingCurve() curves.PairingCurve {
	return NewPairingCurve()
}

func (*PointG1) OtherPrimeAlgebraicSubGroup() curves.Curve {
	return NewG2()
}

func (*PointG1) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
	//if order.Nat().Eq(p.Curve().SubGroupOrder().Nat()) == 1 {
	//	return p.V.InCorrectSubgroup() == 1
	//}
	//e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	//return p.Mul(e).IsIdentity()
}

func (p *PointG1) Pair(rhs curves.PairingPoint) curves.GtMember {
	e := new(bls12381impl.Engine)
	e.AddPair(p.V, rhs.(*PointG2).V)

	value := e.Result()

	return &GtMember{V: value}
}

// === Coordinate Interface Methods.

func (p *PointG1) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *PointG1) AffineX() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: p.V.GetX(),
	}
}

func (p *PointG1) AffineY() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: p.V.GetY(),
	}
}

func (p *PointG1) ProjectiveX() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: &p.V.X,
	}
}

func (p *PointG1) ProjectiveY() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: &p.V.Y,
	}
}

func (p *PointG1) ProjectiveZ() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: &p.V.Z,
	}
}

// === Serialisation.

func (p *PointG1) ToAffineCompressed() []byte {
	out := p.V.ToCompressed()
	return out[:]
}

func (p *PointG1) ToAffineUncompressed() []byte {
	out := p.V.ToUncompressed()
	return out[:]
}

func (*PointG1) FromAffineCompressed(input []byte) (curves.Point, error) {
	var b [bls12381impl.FieldBytes]byte
	copy(b[:], input)
	value, err := new(bls12381impl.G1).FromCompressed(&b)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't construct G1 point from affine compressed")
	}
	return &PointG1{V: value}, nil
}

func (*PointG1) FromAffineUncompressed(input []byte) (curves.Point, error) {
	var b [96]byte
	copy(b[:], input)
	value, err := new(bls12381impl.G1).FromUncompressed(&b)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't construct G1 point from affine uncompressed")
	}
	return &PointG1{V: value}, nil
}

func (p *PointG1) MarshalBinary() ([]byte, error) {
	res := impl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *PointG1) UnmarshalBinary(input []byte) error {
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
	ppt, ok := pt.(*PointG1)
	if !ok {
		return errs.NewType("invalid point")
	}
	p.V = ppt.V
	return nil
}

func (p *PointG1) MarshalJSON() ([]byte, error) {
	res, err := impl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *PointG1) UnmarshalJSON(input []byte) error {
	pt, err := impl.UnmarshalJson(p.Curve().Name(), p.FromAffineCompressed, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	P, ok := pt.(*PointG1)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V = P.V
	return nil
}

// === Hashable.

func (p *PointG1) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}
