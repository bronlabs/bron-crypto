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

var _ curves.Point = (*PallasPoint)(nil)
var _ encoding.BinaryMarshaler = (*PallasPoint)(nil)
var _ encoding.BinaryUnmarshaler = (*PallasPoint)(nil)
var _ json.Unmarshaler = (*PallasPoint)(nil)

type PallasPoint struct {
	V pastaImpl.PallasPoint

	_ ds.Incomparable
}

func NewPallasPoint() *PallasPoint {
	return NewPallasCurve().AdditiveIdentity().(*PallasPoint)
}

func (*PallasPoint) Structure() curves.Curve {
	return NewPallasCurve()
}

func (p *PallasPoint) Unwrap() curves.Point {
	return p
}

func (*PallasPoint) ApplyOp(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasPoint) IsInPrimeSubGroup() bool {
	return true
}

func (p *PallasPoint) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (*PallasPoint) IsBasePoint() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasPoint) CanGenerateAllElements() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasPoint) IsDesignatedGenerator() bool {
	//TODO implement me
	panic("implement me")
}

func (p *PallasPoint) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*PallasPoint)
	if !ok {
		return false
	}
	return p.V.Equals(&r.V) == 1
}

func (p *PallasPoint) Clone() curves.Point {
	clone := new(PallasPoint)
	clone.V.Set(&p.V)
	return clone
}

// === Groupoid Methods.

func (p *PallasPoint) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *PallasPoint) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.ScalarMul(NewPallasCurve().Scalar().SetNat(n))
}

func (*PallasPoint) Order(op algebra.BinaryOperator[curves.Point]) (*saferith.Modulus, error) {
	panic("implement me")
}

// === Additive Groupoid Methods.

func (p *PallasPoint) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PallasPoint)
	if !ok {
		panic("rhs is not a pallas point")
	}

	result := new(PallasPoint)
	result.V.Add(&p.V, &r.V)
	return result
}

func (p *PallasPoint) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewPallasScalarField().Element().SetNat(n)))
}

func (p *PallasPoint) Double() curves.Point {
	result := new(PallasPoint)
	result.V.Double(&p.V)
	return result
}

func (p *PallasPoint) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*PallasPoint) IsIdentity(under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *PallasPoint) IsAdditiveIdentity() bool {
	return p.V.IsIdentity() == 1
}

// === Group Methods.

func (*PallasPoint) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

func (*PallasPoint) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Group Methods.

func (p *PallasPoint) AdditiveInverse() curves.Point {
	result := new(PallasPoint)
	result.V.Neg(&p.V)
	return result
}

func (p *PallasPoint) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *PallasPoint) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PallasPoint)
	if !ok {
		panic("rhs is not a pallas point")
	}

	result := new(PallasPoint)
	result.V.Sub(&p.V, &r.V)
	return result
}

func (p *PallasPoint) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Sub(q.Unwrap().ScalarMul(NewPallasScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *PallasPoint) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	s, ok := rhs.(*PallasScalar)
	if !ok {
		panic("rhs is not a pallas point")
	}

	result := new(PallasPoint)
	pointsImpl.ScalarMul[*pastaImpl.Fp](&result.V, &p.V, s.V.Bytes())
	return result
}

// === Curve Methods.

func (*PallasPoint) Curve() curves.Curve {
	return &pallasInstance
}

func (p *PallasPoint) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (p *PallasPoint) IsNegative() bool {
	var x, y pastaImpl.Fp
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		return false
	}

	return y.Bytes()[0]&0b1 == 1
}

func (*PallasPoint) IsSmallOrder() bool {
	return false
}

func (*PallasPoint) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

func (p *PallasPoint) ClearCofactor() curves.Point {
	return p.Clone()
}

// === Coordinates interface methods.

func (p *PallasPoint) AffineCoordinates() []curves.BaseFieldElement {
	x := new(PallasBaseFieldElement)
	y := new(PallasBaseFieldElement)
	ok := p.V.ToAffine(&x.V, &y.V)
	if ok != 1 {
		return []curves.BaseFieldElement{
			p.Curve().BaseField().AdditiveIdentity(),
			p.Curve().BaseField().AdditiveIdentity(),
		}
	}

	return []curves.BaseFieldElement{x, y}
}

func (p *PallasPoint) AffineX() curves.BaseFieldElement {
	return p.AffineCoordinates()[0]
}

func (p *PallasPoint) AffineY() curves.BaseFieldElement {
	return p.AffineCoordinates()[1]
}

// === Serialisation.

func (p *PallasPoint) ToAffineCompressed() []byte {
	// Use ZCash encoding where infinity is all zeros and the top bit represents the sign of y
	// and the remainder represent the x-coordinate
	if p.IsAdditiveIdentity() {
		var zeros [pastaImpl.FpBytes]byte
		return zeros[:]
	}

	var x, y pastaImpl.Fp
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}
	sign := (y.Bytes()[0] & 0b1) << 7
	result := x.Bytes()
	result[31] |= sign
	return result
}

func (p *PallasPoint) ToAffineUncompressed() []byte {
	if p.IsAdditiveIdentity() {
		var zeros [pastaImpl.FpBytes * 2]byte
		return zeros[:]
	}

	var x, y pastaImpl.Fp
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}

	return slices.Concat(x.Bytes(), y.Bytes())
}

func (p *PallasPoint) FromAffineCompressed(input []byte) (curves.Point, error) {
	if len(input) != pastaImpl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	sign := input[31] >> 7
	var buffer [pastaImpl.FpBytes]byte
	copy(buffer[:], input)
	buffer[31] &= 0x7f

	var x, y pastaImpl.Fp
	ok := x.SetBytes(buffer[:])
	if ok != 1 {
		return nil, errs.NewLength("invalid input")
	}
	if x.IsZero() == 1 && sign == 0 {
		return p.Curve().AdditiveIdentity(), nil
	}

	pp := new(PallasPoint)
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

func (p *PallasPoint) FromAffineUncompressed(input []byte) (curves.Point, error) {
	if len(input) != 2*pastaImpl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var x, y pastaImpl.Fp
	ok := x.SetBytes(input[:pastaImpl.FpBytes])
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	ok = y.SetBytes(input[pastaImpl.FpBytes:])
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	if x.IsZero() == 1 && y.IsZero() == 1 {
		return p.Curve().AdditiveIdentity(), nil
	}

	pp := new(PallasPoint)
	ok = pp.V.SetAffine(&x, &y)
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	return pp, nil
}

func (p *PallasPoint) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *PallasPoint) UnmarshalBinary(input []byte) error {
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
	ppt, ok := pt.(*PallasPoint)
	if !ok {
		return errs.NewType("invalid point")
	}
	p.V.Set(&ppt.V)
	return nil
}

func (p *PallasPoint) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *PallasPoint) UnmarshalJSON(input []byte) error {
	pt, err := curvesImpl.UnmarshalJson(p.Curve().Name(), p.FromAffineCompressed, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	P, ok := pt.(*PallasPoint)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V.Set(&P.V)
	return nil
}

// === Hashable.

func (p *PallasPoint) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}
