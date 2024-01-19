package bls12381

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var _ curves.PairingPoint = (*PointG2)(nil)
var _ curves.ProjectiveCurveCoordinates = (*PointG2)(nil)
var _ encoding.BinaryMarshaler = (*PointG1)(nil)
var _ encoding.BinaryUnmarshaler = (*PointG1)(nil)
var _ json.Unmarshaler = (*PointG2)(nil)

type PointG2 struct {
	V *bls12381impl.G2

	_ types.Incomparable
}

func NewPointG2() *PointG2 {
	return NewG2().Identity().(*PointG2)
}

// === Basic Methods.

func (p *PointG2) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*PointG2)
	if ok {
		return p.V.Equal(r.V) == 1
	} else {
		return false
	}
}

func (p *PointG2) Clone() curves.Point {
	return &PointG2{V: new(bls12381impl.G2).Set(p.V)}
}

// === Groupoid Methods.

func (p *PointG2) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *PointG2) OperateIteratively(q curves.Point, n *saferith.Nat) curves.Point {
	return p.ApplyAdd(q, n)
}

func (p *PointG2) Order() *saferith.Modulus {
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

func (p *PointG2) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG2)
	if ok {
		return &PointG2{V: new(bls12381impl.G2).Add(p.V, r.V)}
	} else {
		panic("rhs is not PointBls12381G2")
	}
}

func (p *PointG2) ApplyAdd(q curves.Point, n *saferith.Nat) curves.Point {
	return p.Add(q.Mul(NewScalarFieldG2().Element().SetNat(n)))
}

func (p *PointG2) Double() curves.Point {
	return &PointG2{V: new(bls12381impl.G2).Double(p.V)}
}

func (p *PointG2) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (p *PointG2) IsIdentity() bool {
	return p.V.IsIdentity() == 1
}

// === Additive Monoid Methods.

func (p *PointG2) IsAdditiveIdentity() bool {
	return p.IsIdentity()
}

// === Group Methods.

func (p *PointG2) Inverse() curves.Point {
	return &PointG2{V: new(bls12381impl.G2).Neg(p.V)}
}

func (p *PointG2) IsInverse(of curves.Point) bool {
	return p.Operate(of).IsIdentity()
}

// === Additive Group Methods.

func (p *PointG2) AdditiveInverse() curves.Point {
	return p.Inverse()
}

func (p *PointG2) IsAdditiveInverse(of curves.Point) bool {
	return p.IsInverse(of)
}

func (p *PointG2) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG2)
	if ok {
		return &PointG2{V: new(bls12381impl.G2).Sub(p.V, r.V)}
	} else {
		panic("rhs is not PointBls12381G2")
	}
}

func (p *PointG2) ApplySub(q curves.Point, n *saferith.Nat) curves.Point {
	return p.Sub(q.Mul(NewScalarFieldG2().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *PointG2) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		return &PointG2{V: new(bls12381impl.G2).Mul(p.V, r.V)}
	} else {
		panic("rhs is not ScalarBls12381G2")
	}
}

// === Curve Methods.

func (*PointG2) Curve() curves.Curve {
	return NewG2()
}

func (p *PointG2) Neg() curves.Point {
	return p.Inverse()
}

func (p *PointG2) IsNegative() bool {
	// According to https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
	// This bit represents the sign of the `y` coordinate which is what we want
	return (p.V.ToCompressed()[0]>>5)&1 == 1
}

func (p *PointG2) IsSmallOrder() bool {
	return p.ClearCofactor().IsIdentity()
}

func (p *PointG2) ClearCofactor() curves.Point {
	return &PointG2{V: new(bls12381impl.G2).ClearCofactor(p.V)}
}

// === Pairing Methods.

func (*PointG2) PairingCurve() curves.PairingCurve {
	return NewPairingCurve()
}

func (*PointG2) OtherPrimeAlgebraicSubGroup() curves.Curve {
	return NewG1()
}

func (p *PointG2) IsTorsionElement(order *saferith.Modulus) bool {
	if order.Nat().Eq(p.Curve().SubGroupOrder().Nat()) == 1 {
		return p.V.InCorrectSubgroup() == 1
	}
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.Mul(e).IsIdentity()
}

func (p *PointG2) Pair(rhs curves.PairingPoint) curves.GtMember {
	pt, ok := rhs.(*PointG1)
	if !ok {
		panic("rhs is not in G1")
	}
	e := new(bls12381impl.Engine)
	e.AddPair(pt.V, p.V)

	value := e.Result()

	return &GtMember{V: value}
}

// === Coordinate Interface Methods.

func (p *PointG2) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *PointG2) AffineX() curves.BaseFieldElement {
	return &BaseFieldElementG2{
		V: p.V.GetX(),
	}
}

func (p *PointG2) AffineY() curves.BaseFieldElement {
	return &BaseFieldElementG2{
		V: p.V.GetY(),
	}
}

func (p *PointG2) ProjectiveX() curves.BaseFieldElement {
	return &BaseFieldElementG2{
		V: &p.V.X,
	}
}

func (p *PointG2) ProjectiveY() curves.BaseFieldElement {
	return &BaseFieldElementG2{
		V: &p.V.Y,
	}
}

func (p *PointG2) ProjectiveZ() curves.BaseFieldElement {
	return &BaseFieldElementG2{
		V: &p.V.Z,
	}
}

// === Serialisation.

func (p *PointG2) ToAffineCompressed() []byte {
	out := p.V.ToCompressed()
	return out[:]
}

func (p *PointG2) ToAffineUncompressed() []byte {
	out := p.V.ToUncompressed()
	return out[:]
}

func (*PointG2) FromAffineCompressed(input []byte) (curves.Point, error) {
	var b [bls12381impl.WideFieldBytes]byte
	copy(b[:], input)
	value, err := new(bls12381impl.G2).FromCompressed(&b)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't construct G2 from affine compressed")
	}
	return &PointG2{V: value}, nil
}

func (*PointG2) FromAffineUncompressed(input []byte) (curves.Point, error) {
	var b [bls12381impl.WideFieldBytesFp2]byte
	copy(b[:], input)
	value, err := new(bls12381impl.G2).FromUncompressed(&b)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't construct G2 from affine uncompressed")
	}
	return &PointG2{V: value}, nil
}

func (p *PointG2) MarshalBinary() ([]byte, error) {
	res := impl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *PointG2) UnmarshalBinary(input []byte) error {
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
	ppt, ok := pt.(*PointG2)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.V = ppt.V
	return nil
}

func (p *PointG2) MarshalJSON() ([]byte, error) {
	res, err := impl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *PointG2) UnmarshalJSON(input []byte) error {
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
	P, ok := pt.(*PointG2)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V = P.V
	return nil
}
