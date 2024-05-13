package kuiper

import (
	"encoding"
	"encoding/binary"
	"encoding/json"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb7"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl/fq"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	curvesImpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var (
	_ curves.Point                      = (*ErisPoint)(nil)
	_ curves.ProjectiveCurveCoordinates = (*ErisPoint)(nil)
	_ encoding.BinaryMarshaler          = (*ErisPoint)(nil)
	_ encoding.BinaryUnmarshaler        = (*ErisPoint)(nil)
	_ json.Unmarshaler                  = (*ErisPoint)(nil)
)

type ErisPoint struct {
	V *limb7.EllipticPoint

	_ ds.Incomparable
}

func NewErisPoint() *ErisPoint {
	return NewErisCurve().AdditiveIdentity().(*ErisPoint)
}

// === Basic Methods.

func (*ErisPoint) Structure() curves.Curve {
	return NewErisCurve()
}

func (p *ErisPoint) Unwrap() curves.Point {
	return p
}

func (*ErisPoint) ApplyOp(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (p *ErisPoint) IsInPrimeSubGroup() bool {
	return p.V.IsOnCurve() || p.IsAdditiveIdentity()
}

func (p *ErisPoint) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (p *ErisPoint) IsBasePoint() bool {
	return NewErisCurve().Generator().Equal(p)
}

func (p *ErisPoint) CanGenerateAllElements() bool {
	return p.IsInPrimeSubGroup()
}

func (p *ErisPoint) IsDesignatedGenerator() bool {
	return p.IsBasePoint()
}

func (p *ErisPoint) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*ErisPoint)
	if ok {
		return p.V.Equal(r.V) == 1
	} else {
		return false
	}
}

func (p *ErisPoint) Clone() curves.Point {
	return &ErisPoint{
		V: impl.ErisPointNew().Set(p.V),
	}
}

// === Groupoid Methods.

func (p *ErisPoint) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *ErisPoint) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.Unwrap().ScalarMul(NewErisCurve().Scalar().SetNat(n))
}

func (*ErisPoint) Order(op algebra.BinaryOperator[curves.Point]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
	//if p.IsIdentity() {
	//	return saferith.ModulusFromUint64(0), nil
	//}
	//q := p.Clone()
	//order := saferithUtils.NatOne
	//for !q.IsIdentity() {
	//	q = q.Add(p)
	//	saferithUtils.NatInc(order)
	//}
	//return saferith.ModulusFromNat(order), nil
}

// === Additive Groupoid Methods.

func (p *ErisPoint) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ErisPoint)
	if ok {
		value := impl.ErisPointNew().Add(p.V, r.V)
		return &ErisPoint{V: value}
	} else {
		panic("rhs is not Eris Point")
	}
}

func (p *ErisPoint) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewErisScalarField().Element().SetNat(n)))
}

func (p *ErisPoint) Double() curves.Point {
	value := impl.ErisPointNew().Double(p.V)
	return &ErisPoint{V: value}
}

func (p *ErisPoint) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*ErisPoint) IsIdentity(under algebra.BinaryOperator[curves.Point]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *ErisPoint) IsAdditiveIdentity() bool {
	return p.V.IsIdentity()
}

// === Group Methods.

func (*ErisPoint) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisPoint) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

// === Additive Group Methods.

func (p *ErisPoint) AdditiveInverse() curves.Point {
	value := impl.ErisPointNew().Neg(p.V)
	return &ErisPoint{V: value}
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
		value := impl.ErisPointNew().Sub(p.V, r.V)
		return &ErisPoint{V: value}
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
		value := impl.ErisPointNew().Mul(p.V, r.V)
		return &ErisPoint{V: value}
	} else {
		panic("rhs is not Eris scalar")
	}
}

// === Curve Methods.

func (*ErisPoint) Curve() curves.Curve {
	return NewErisCurve()
}

func (p *ErisPoint) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (p *ErisPoint) IsNegative() bool {
	return p.V.GetY().Value[0]&1 == 1
}

func (*ErisPoint) IsSmallOrder() bool {
	return false
}

func (*ErisPoint) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (p *ErisPoint) ClearCofactor() curves.Point {
	return p.Clone()
}

// === Coordinates interface methods.

func (p *ErisPoint) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *ErisPoint) AffineX() curves.BaseFieldElement {
	return &ErisBaseFieldElement{
		V: p.V.GetX(),
	}
}

func (p *ErisPoint) AffineY() curves.BaseFieldElement {
	return &ErisBaseFieldElement{
		V: p.V.GetY(),
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
	var x [33]byte
	x[0] = byte(2)

	t := impl.ErisPointNew().ToAffine(p.V)

	x[0] |= t.Y.Bytes()[0] & 1

	xBytes := t.X.Bytes()
	copy(x[1:], bitstring.ReverseBytes(xBytes[:]))
	return x[:]
}

func (p *ErisPoint) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	t := impl.ErisPointNew().ToAffine(p.V)
	arr := t.X.Bytes()
	copy(out[1:33], bitstring.ReverseBytes(arr[:]))
	arr = t.Y.Bytes()
	copy(out[33:], bitstring.ReverseBytes(arr[:]))
	return out[:]
}

func (*ErisPoint) FromAffineCompressed(input []byte) (curves.Point, error) {
	var raw [limb7.FieldBytes]byte
	if len(input) != 33 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	sign := int(input[0])
	if sign != 2 && sign != 3 {
		return nil, errs.NewFailed("invalid sign byte")
	}
	sign &= 0x1

	copy(raw[:], bitstring.ReverseBytes(input[1:]))
	x, err := fq.New().SetBytes(&raw)
	if err != nil {
		return nil, errs.WrapCoordinates(err, "x")
	}

	value := impl.ErisPointNew().Identity()
	rhs := fq.New()
	value.Arithmetic.RhsEquation(rhs, x)
	// test that rhs is quadratic residue
	// if not, then this Point is at infinity
	y, wasQr := fq.New().Sqrt(rhs)
	if wasQr {
		// fix the sign
		sigY := int(y.Bytes()[0] & 1)
		if sigY != sign {
			y.Neg(y)
		}
		value.X = x
		value.Y = y
		value.Z.SetOne()
	}
	return &ErisPoint{V: value}, nil
}

func (*ErisPoint) FromAffineUncompressed(input []byte) (curves.Point, error) {
	var arr [limb7.FieldBytes]byte
	if len(input) != 65 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	if input[0] != 4 {
		return nil, errs.NewFailed("invalid sign byte")
	}

	copy(arr[:], bitstring.ReverseBytes(input[1:33]))
	x, err := fq.New().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapCoordinates(err, "x")
	}
	copy(arr[:], bitstring.ReverseBytes(input[33:]))
	y, err := fq.New().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapCoordinates(err, "y")
	}
	value := impl.ErisPointNew()
	value.X = x
	value.Y = y
	value.Z.SetOne()
	if !value.IsOnCurve() {
		return nil, errs.NewMembership("deserialised value is not on curve")
	}
	return &ErisPoint{V: value}, nil
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
