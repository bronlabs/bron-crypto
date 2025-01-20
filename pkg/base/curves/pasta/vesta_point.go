package pasta

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
	pastaImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

var _ curves.Point = (*VestaPoint)(nil)
var _ encoding.BinaryMarshaler = (*VestaPoint)(nil)
var _ encoding.BinaryUnmarshaler = (*VestaPoint)(nil)
var _ json.Unmarshaler = (*VestaPoint)(nil)

type VestaPoint struct {
	V pastaImpl.VestaPoint

	_ ds.Incomparable
}

func NewVestaPoint() *VestaPoint {
	return NewVestaCurve().AdditiveIdentity().(*VestaPoint)
}

func (*VestaPoint) Structure() curves.Curve {
	return NewVestaCurve()
}

func (p *VestaPoint) Unwrap() curves.Point {
	return p
}

func (*VestaPoint) ApplyOp(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaPoint) IsInPrimeSubGroup() bool {
	return true
}

func (p *VestaPoint) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (*VestaPoint) IsBasePoint() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaPoint) CanGenerateAllElements() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaPoint) IsDesignatedGenerator() bool {
	//TODO implement me
	panic("implement me")
}

func (p *VestaPoint) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*VestaPoint)
	if !ok {
		return false
	}
	return p.V.Equals(&r.V) == 1
}

func (p *VestaPoint) Clone() curves.Point {
	clone := new(VestaPoint)
	clone.V.Set(&p.V)
	return clone
}

// === Groupoid Methods.

func (p *VestaPoint) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *VestaPoint) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.ScalarMul(NewVestaCurve().Scalar().SetNat(n))
}

func (*VestaPoint) Order(op algebra.BinaryOperator[curves.Point]) (*saferith.Modulus, error) {
	panic("implement me")
}

// === Additive Groupoid Methods.

func (p *VestaPoint) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*VestaPoint)
	if !ok {
		panic("rhs is not a vesta point")
	}

	result := new(VestaPoint)
	result.V.Add(&p.V, &r.V)
	return result
}

func (p *VestaPoint) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewVestaScalarField().Element().SetNat(n)))
}

func (p *VestaPoint) Double() curves.Point {
	result := new(VestaPoint)
	result.V.Double(&p.V)
	return result
}

func (p *VestaPoint) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*VestaPoint) IsIdentity(under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *VestaPoint) IsAdditiveIdentity() bool {
	return p.V.IsIdentity() == 1
}

// === Group Methods.

func (*VestaPoint) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

func (*VestaPoint) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Group Methods.

func (p *VestaPoint) AdditiveInverse() curves.Point {
	result := new(VestaPoint)
	result.V.Neg(&p.V)
	return result
}

func (p *VestaPoint) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *VestaPoint) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*VestaPoint)
	if !ok {
		panic("rhs is not a vesta point")
	}

	result := new(VestaPoint)
	result.V.Sub(&p.V, &r.V)
	return result
}

func (p *VestaPoint) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Sub(q.Unwrap().ScalarMul(NewVestaScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *VestaPoint) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	s, ok := rhs.(*VestaScalar)
	if !ok {
		panic("rhs is not a vesta point")
	}

	result := new(VestaPoint)
	pointsImpl.ScalarMul[*pastaImpl.Fq](&result.V, &p.V, s.V.Bytes())
	return result
}

// === Curve Methods.

func (*VestaPoint) Curve() curves.Curve {
	return &vestaInstance
}

func (p *VestaPoint) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (p *VestaPoint) IsNegative() bool {
	var x, y pastaImpl.Fq
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		return false
	}

	return y.Bytes()[0]&0b1 == 1
}

func (*VestaPoint) IsSmallOrder() bool {
	return false
}

func (*VestaPoint) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

func (p *VestaPoint) ClearCofactor() curves.Point {
	return p.Clone()
}

// === Coordinates interface methods.

func (p *VestaPoint) AffineCoordinates() []curves.BaseFieldElement {
	x := new(VestaBaseFieldElement)
	y := new(VestaBaseFieldElement)
	ok := p.V.ToAffine(&x.V, &y.V)
	if ok != 1 {
		return []curves.BaseFieldElement{
			p.Curve().BaseField().AdditiveIdentity(),
			p.Curve().BaseField().AdditiveIdentity(),
		}
	}

	return []curves.BaseFieldElement{x, y}
}

func (p *VestaPoint) AffineX() curves.BaseFieldElement {
	return p.AffineCoordinates()[0]
}

func (p *VestaPoint) AffineY() curves.BaseFieldElement {
	return p.AffineCoordinates()[1]
}

// === Serialisation.

func (p *VestaPoint) ToAffineCompressed() []byte {
	// Use ZCash encoding where infinity is all zeros and the top bit represents the sign of y
	// and the remainder represent the x-coordinate
	if p.IsAdditiveIdentity() {
		var zeros [pastaImpl.FqBytes]byte
		return zeros[:]
	}

	var x, y pastaImpl.Fq
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}
	sign := (y.Bytes()[0] & 0b1) << 7
	result := x.Bytes()
	result[31] |= sign
	return result
}

func (p *VestaPoint) ToAffineUncompressed() []byte {
	if p.IsAdditiveIdentity() {
		var zeros [pastaImpl.FqBytes * 2]byte
		return zeros[:]
	}

	var x, y pastaImpl.Fq
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}

	return slices.Concat(x.Bytes(), y.Bytes())
}

func (p *VestaPoint) FromAffineCompressed(input []byte) (curves.Point, error) {
	if len(input) != pastaImpl.FqBytes {
		return nil, errs.NewLength("invalid input")
	}

	sign := input[31] >> 7
	var buffer [pastaImpl.FqBytes]byte
	copy(buffer[:], input)
	buffer[31] &= 0x7f

	var x, y pastaImpl.Fq
	ok := x.SetBytes(buffer[:])
	if ok != 1 {
		return nil, errs.NewLength("invalid input")
	}
	if x.IsZero() == 1 && sign == 0 {
		return p.Curve().AdditiveIdentity(), nil
	}

	pp := new(VestaPoint)
	ok = pp.V.SetFromAffineX(&x)
	if ok != 1 {
		return nil, errs.NewLength("invalid input")
	}
	ok = pp.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}

	if (y.Bytes()[0] & 0b1) != sign {
		pp.V.Neg(&pp.V)
	}
	return pp, nil
}

func (p *VestaPoint) FromAffineUncompressed(input []byte) (curves.Point, error) {
	if len(input) != 2*pastaImpl.FqBytes {
		return nil, errs.NewLength("invalid input")
	}

	var x, y pastaImpl.Fq
	ok := x.SetBytes(input[:pastaImpl.FqBytes])
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	ok = y.SetBytes(input[pastaImpl.FqBytes:])
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	if x.IsZero() == 1 && y.IsZero() == 1 {
		return p.Curve().AdditiveIdentity(), nil
	}

	pp := new(VestaPoint)
	ok = pp.V.SetAffine(&x, &y)
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	return pp, nil
}

func (p *VestaPoint) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *VestaPoint) UnmarshalBinary(input []byte) error {
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
	ppt, ok := pt.(*VestaPoint)
	if !ok {
		return errs.NewType("invalid point")
	}
	p.V.Set(&ppt.V)
	return nil
}

func (p *VestaPoint) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *VestaPoint) UnmarshalJSON(input []byte) error {
	pt, err := curvesImpl.UnmarshalJson(p.Curve().Name(), p.FromAffineCompressed, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	P, ok := pt.(*VestaPoint)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V.Set(&P.V)
	return nil
}

// === Hashable.

func (p *VestaPoint) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}
