package curve25519

import (
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"encoding/json"

	"github.com/cronokirby/saferith"
	curve25519n "golang.org/x/crypto/curve25519"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ curves.Point = (*Point)(nil)
var _ encoding.BinaryMarshaler = (*Point)(nil)
var _ encoding.BinaryUnmarshaler = (*Point)(nil)
var _ json.Unmarshaler = (*Point)(nil)

type Point struct {
	V [32]byte

	_ ds.Incomparable
}

// === Basic Methods.

func (*Point) Structure() curves.Curve {
	return NewCurve()
}

func (p *Point) Unwrap() curves.Point {
	return p
}

func (*Point) Apply(operator algebra.Operator, x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
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

func (*Point) IsBasePoint() bool {
	//TODO implement me
	panic("implement me")
}

func (*Point) IsInvolution(under algebra.Operator) (bool, error) {
	panic("implement me")
}
func (*Point) IsInvolutionUnderAddition() bool {
	panic("implement me")
}
func (p *Point) CanGenerateAllElements(under algebra.Operator) bool {
	return p.IsInPrimeSubGroup()
}

func (*Point) IsDesignatedGenerator() bool {
	//TODO implement me
	panic("implement me")
}

func (p *Point) Equal(rhs curves.Point) bool {
	return subtle.ConstantTimeCompare(p.V[:], rhs.(*Point).V[:]) == 1
}

func (p *Point) Clone() curves.Point {
	return &Point{
		V: p.V,
	}
}

// === Groupoid Methods.

func (p *Point) Operate(op algebra.Operator, rhs algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	panic("not implemented")
}

func (p *Point) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.ScalarMul(NewCurve().Scalar().SetNat(n))
}

func (*Point) Order(op algebra.Operator) (*saferith.Nat, error) {
	panic("implement me")
}

// === Additive Groupoid Methods.

func (*Point) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	panic("not implemented")
}

func (p *Point) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewScalarField().Element().SetNat(n)))
}

func (*Point) Double() curves.Point {
	panic("not implemented")
}

func (p *Point) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*Point) IsIdentity(under algebra.Operator) (bool, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *Point) IsAdditiveIdentity() bool {
	return p.Equal(p.Curve().AdditiveIdentity())
}

// === Group Methods.

func (*Point) Inverse(under algebra.Operator) (curves.Point, error) {
	panic("not implemented")
}

func (*Point) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.Operator) (bool, error) {
	panic("implement me")
}

// === Additive Group Methods.

func (*Point) AdditiveInverse() curves.Point {
	panic("not implemented")
}

func (p *Point) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (*Point) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	panic("not implemented")
}

func (p *Point) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Sub(q.Unwrap().ScalarMul(NewScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *Point) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	s, ok := rhs.(*Scalar)
	if !ok {
		panic("invalid type")
	}
	ss, err := curve25519n.X25519(
		s.Bytes(),
		p.V[:],
	)
	if err != nil {
		panic(err)
	}
	var result [32]byte
	copy(result[:], ss)
	return &Point{V: result}
}

// === Curve Methods.

func (*Point) Curve() curves.Curve {
	return NewCurve()
}

func (p *Point) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (*Point) IsNegative() bool {
	panic("not implemented")
}

func (*Point) ClearCofactor() curves.Point {
	panic("not implemented")
}

func (p *Point) IsSmallOrder() bool {
	outsidePrimeSubgroupValues := [12][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0},
		{95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87},
		{236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{205, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 128},
		{76, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 215},
		{217, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{218, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{219, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 25},
	}

	for _, testValue := range outsidePrimeSubgroupValues {
		if subtle.ConstantTimeCompare(p.V[:], testValue) == 1 {
			panic("Invalid public key")
		}
	}
	return true
}

func (*Point) IsTorsionElement(order *saferith.Modulus, under algebra.Operator) (bool, error) {
	panic("not implemented")
}

// === Misc.

func (p *Point) X25519(sc curves.Scalar) curves.Point {
	return p.ScalarMul(sc)
}

// === Coordinates.

func (p *Point) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *Point) AffineX() curves.BaseFieldElement {
	return &BaseFieldElement{V: p.V}
}

func (*Point) AffineY() curves.BaseFieldElement {
	panic("not implemented")
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
	return p.V[:]
}

func (p *Point) ToAffineUncompressed() []byte {
	return p.V[:]
}

func (*Point) FromAffineCompressed(inBytes []byte) (curves.Point, error) {
	panic("not implemented")
}

func (*Point) FromAffineUncompressed(inBytes []byte) (curves.Point, error) {
	panic("not implemented")
}

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

// === Hashable.

func (p *Point) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}
