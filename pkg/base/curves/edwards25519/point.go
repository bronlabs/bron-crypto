package edwards25519

import (
	"encoding"
	"encoding/binary"
	"encoding/json"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519/impl"
	curvesImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

var _ curves.Point = (*Point)(nil)
var _ encoding.BinaryMarshaler = (*Point)(nil)
var _ encoding.BinaryUnmarshaler = (*Point)(nil)
var _ json.Unmarshaler = (*Point)(nil)

type Point struct {
	V edwards25519Impl.Point
}

func NewPoint() *Point {
	result := new(Point)
	result.V.SetIdentity()
	return result
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
	qMinusOne := p.Curve().ScalarField().One().Neg()
	return p.ScalarMul(qMinusOne).Add(p).IsAdditiveIdentity()
}

func (p *Point) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	if _, _, less := order.Cmp(subgroupOrder); less != 0 {
		// TODO implement me: decompose the order into an additive combination of
		// elements below the subgroup order.
		panic("order is greater than subgroup order. Implement me ()")
	}
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
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
	rhsP, ok := rhs.(*Point)
	if !ok {
		return false
	}

	return p.V.Equals(&rhsP.V) == 1
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
	if !ok {
		panic("rhs in not PointEd25519")
	}

	result := new(Point)
	result.V.Add(&p.V, &r.V)
	return result
}

func (p *Point) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewScalarField().Element().SetNat(n)))
}

func (p *Point) Double() curves.Point {
	result := new(Point)
	result.V.Double(&p.V)
	return result
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
	result := new(Point)
	result.V.Neg(&p.V)
	return result
}

func (p *Point) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *Point) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs in nil")
	}
	r, ok := rhs.(*Point)
	if !ok {
		panic("rhs in not PointEd25519")
	}

	result := new(Point)
	result.V.Sub(&p.V, &r.V)
	return result
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
	if !ok {
		panic("rhs in not ScalarEd25519")
	}

	result := new(Point)
	result.V.ScalarMul(&p.V, &r.V)
	return result
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
	result := new(Point)
	result.V.ClearCofactor(&p.V)
	return result
}

func (p *Point) IsSmallOrder() bool {
	// pBytes := p.ToAffineCompressed()
	// pHex := hex.EncodeToString(pBytes)

	// for _, smallOrderAffinecurves.Point[Edwards25519] := range []string{
	// 	"0100000000000000000000000000000000000000000000000000000000000000",
	// 	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	// 	"0000000000000000000000000000000000000000000000000000000000000080",
	// 	"0000000000000000000000000000000000000000000000000000000000000000",
	// 	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	// 	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	// 	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	// 	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	// } {
	// 	if pHex == smallOrderAffinecurves.Point[Edwards25519] {
	// 		return true
	// 	}
	// }
	// return false

	// performance difference is negligible
	return p.ClearCofactor().IsAdditiveIdentity()
}

func (*Point) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Coordinates.

func (p *Point) AffineCoordinates() []curves.BaseFieldElement {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)

	return []curves.BaseFieldElement{&x, &y}
}

func (p *Point) AffineX() curves.BaseFieldElement {
	return p.AffineCoordinates()[0]
}

func (p *Point) AffineY() curves.BaseFieldElement {
	return p.AffineCoordinates()[1]
}

// === Serialisation.

func (p *Point) ToAffineCompressed() []byte {
	return p.V.V.Bytes()
}

func (p *Point) ToAffineUncompressed() []byte {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)

	return slices.Concat(x.V.Bytes(), y.V.Bytes())
}

func (*Point) FromAffineCompressed(inBytes []byte) (curves.Point, error) {
	result := new(Point)
	_, err := result.V.V.SetBytes(inBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "invalid bytes sequence")
	}

	return result, nil
}

func (*Point) FromAffineUncompressed(inBytes []byte) (curves.Point, error) {
	if len(inBytes) != 2*32 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	xBytes := inBytes[:32]
	yBytes := inBytes[32:]

	var x, y BaseFieldElement
	ok := x.V.SetBytes(xBytes)
	if ok != 1 {
		return nil, errs.NewCoordinates("x")
	}
	ok = y.V.SetBytes(yBytes)
	if ok != 1 {
		return nil, errs.NewCoordinates("y")
	}

	result := new(Point)
	ok = result.V.SetAffine(&x.V, &y.V)
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
