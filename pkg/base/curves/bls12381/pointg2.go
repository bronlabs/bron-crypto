package bls12381

import (
	"encoding"
	"encoding/binary"
	"encoding/json"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381/impl"
	curvesImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl"
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

var _ curves.PairingPoint = (*PointG2)(nil)
var _ curves.ProjectiveCurveCoordinates = (*PointG2)(nil)
var _ encoding.BinaryMarshaler = (*PointG1)(nil)
var _ encoding.BinaryUnmarshaler = (*PointG1)(nil)
var _ json.Unmarshaler = (*PointG2)(nil)

type PointG2 struct {
	V bls12381Impl.G2Point

	_ ds.Incomparable
}

func NewPointG2() *PointG2 {
	return NewG2().AdditiveIdentity().(*PointG2)
}

// === Basic Methods.

func (*PointG2) Structure() curves.Curve {
	return NewG2()
}

func (p *PointG2) Unwrap() curves.Point {
	return p
}

func (*PointG2) ApplyOp(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (p *PointG2) IsInPrimeSubGroup() bool {
	orderBytes := g2SubGroupOrder.Bytes()
	slices.Reverse(orderBytes)
	var pp bls12381Impl.G2Point
	pointsImpl.ScalarMul[*bls12381Impl.Fp2](&pp, &p.V, orderBytes)
	return pp.IsIdentity() == 1
}

func (p *PointG2) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.ScalarMul(e).IsAdditiveIdentity()
}

func (*PointG2) IsBasePoint() bool {
	//TODO implement me
	panic("implement me")
}

func (*PointG2) CanGenerateAllElements() bool {
	//TODO implement me
	panic("implement me")
}

func (*PointG2) IsDesignatedGenerator() bool {
	//TODO implement me
	panic("implement me")
}

func (p *PointG2) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*PointG2)
	if !ok {
		return false
	}

	return p.V.Equals(&r.V) == 1
}

func (p *PointG2) Clone() curves.Point {
	clone := new(PointG2)
	clone.V.Set(&p.V)
	return clone
}

// === Groupoid Methods.

func (p *PointG2) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *PointG2) OperateIteratively(n *saferith.Nat) curves.Point {
	return p.ScalarMul(NewG2().Scalar().SetNat(n))
}

func (*PointG2) Order(op algebra.BinaryOperator[curves.Point]) (*saferith.Modulus, error) {
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

func (p *PointG2) Add(rhs algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG2)
	if !ok {
		panic("rhs is not PointBls12381G2")
	}

	result := new(PointG2)
	result.V.Add(&p.V, &r.V)
	return result
}

func (p *PointG2) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewScalarFieldG2().Element().SetNat(n)))
}

func (p *PointG2) Double() curves.Point {
	result := new(PointG2)
	result.V.Double(&p.V)
	return result
}

func (p *PointG2) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (*PointG2) IsIdentity(under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (p *PointG2) IsAdditiveIdentity() bool {
	return p.V.IsIdentity() == 1
}

// === Group Methods.

func (*PointG2) Inverse(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

func (*PointG2) IsInverse(of algebra.GroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
}

// === Additive Group Methods.

func (p *PointG2) AdditiveInverse() curves.Point {
	result := new(PointG2)
	result.V.Neg(&p.V)
	return result
}

func (p *PointG2) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *PointG2) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG2)
	if !ok {
		panic("rhs is not PointBls12381G2")
	}

	result := new(PointG2)
	result.V.Sub(&p.V, &r.V)
	return result
}

func (p *PointG2) ApplySub(q algebra.AdditiveGroupElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Sub(q.Unwrap().ScalarMul(NewScalarFieldG2().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *PointG2) ScalarMul(rhs algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if !ok {
		panic("rhs is not ScalarBls12381G2")
	}

	result := new(PointG2)
	pointsImpl.ScalarMulLimbs[*bls12381Impl.Fp2](&result.V, &p.V, r.V.Limbs())
	return result
}

// === Curve Methods.

func (*PointG2) Curve() curves.Curve {
	return NewG2()
}

func (p *PointG2) Neg() curves.Point {
	return p.AdditiveInverse()
}

func (*PointG2) IsNegative() bool {
	panic("implement me")
}

func (p *PointG2) IsSmallOrder() bool {
	return p.ClearCofactor().IsAdditiveIdentity()
}

func (p *PointG2) ClearCofactor() curves.Point {
	hEffBytes := g2HEffective.Bytes()
	slices.Reverse(hEffBytes)

	result := new(PointG2)
	pointsImpl.ScalarMul[*bls12381Impl.Fp2](&result.V, &p.V, hEffBytes)
	return result
}

// === Pairing Methods.

func (*PointG2) PairingCurve() curves.PairingCurve {
	return NewPairingCurve()
}

func (*PointG2) OtherPrimeAlgebraicSubGroup() curves.Curve {
	return NewG1()
}

func (*PointG2) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Point]) (bool, error) {
	panic("implement me")
	//if order.Nat().Eq(p.Curve().SubGroupOrder().Nat()) == 1 {
	//	return p.V.InCorrectSubgroup() == 1
	//}
	//e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	//return p.Mul(e).IsIdentity()
}

func (*PointG2) Pair(rhs curves.PairingPoint) curves.GtMember {
	//pt, ok := rhs.(*PointG1)
	//if !ok {
	//	panic("rhs is not in G1")
	//}
	//e := new(bls12381impl.Engine)
	//e.AddPair(pt.V, p.V)
	//
	//value := e.Result()
	//
	//return &GtMember{V: value}
	panic("implement me")
}

// === Coordinate Interface Methods.

func (p *PointG2) AffineCoordinates() []curves.BaseFieldElement {
	x := new(BaseFieldElementG2)
	y := new(BaseFieldElementG2)
	ok := p.V.ToAffine(&x.V, &y.V)
	if ok != 1 {
		return []curves.BaseFieldElement{
			p.Curve().BaseField().AdditiveIdentity(),
			p.Curve().BaseField().AdditiveIdentity(),
		}
	}

	return []curves.BaseFieldElement{x, y}
}

func (p *PointG2) AffineX() curves.BaseFieldElement {
	return p.AffineCoordinates()[0]
}

func (p *PointG2) AffineY() curves.BaseFieldElement {
	return p.AffineCoordinates()[1]
}

func (p *PointG2) ProjectiveX() curves.BaseFieldElement {
	result := new(BaseFieldElementG2)
	result.V.Set(&p.V.X)
	return result
}

func (p *PointG2) ProjectiveY() curves.BaseFieldElement {
	result := new(BaseFieldElementG2)
	result.V.Set(&p.V.Y)
	return result
}

func (p *PointG2) ProjectiveZ() curves.BaseFieldElement {
	result := new(BaseFieldElementG2)
	result.V.Set(&p.V.Z)
	return result
}

// === Serialisation.

func (p *PointG2) ToAffineCompressed() []byte {
	var x, y bls12381Impl.Fp2
	x.SetZero()
	y.SetZero()
	p.V.ToAffine(&x, &y)
	isInfinity := p.V.IsIdentity()

	x1Bytes := x.U1.Bytes()
	slices.Reverse(x1Bytes)
	x0Bytes := x.U0.Bytes()
	slices.Reverse(x0Bytes)

	out := slices.Concat(x1Bytes, x0Bytes)
	// Compressed flag
	out[0] |= 1 << 7
	// Is infinity
	out[0] |= byte(isInfinity << 6)
	// Sign of y only set if not infinity
	out[0] |= byte((isNegative(&y) & (isInfinity ^ 1)) << 5)
	return out
}

func (p *PointG2) ToAffineUncompressed() []byte {
	var x, y bls12381Impl.Fp2
	x.SetZero()
	y.SetZero()
	isInfinity := p.V.IsIdentity()
	p.V.ToAffine(&x, &y)

	x1Bytes := x.U1.Bytes()
	slices.Reverse(x1Bytes[:])
	x0Bytes := x.U0.Bytes()
	slices.Reverse(x0Bytes[:])
	y1Bytes := y.U1.Bytes()
	slices.Reverse(y1Bytes[:])
	y0Bytes := y.U0.Bytes()
	slices.Reverse(y0Bytes[:])

	out := slices.Concat(x1Bytes, x0Bytes, y1Bytes, y0Bytes)
	out[0] |= byte(isInfinity << 6)
	return out
}

func (*PointG2) FromAffineCompressed(input []byte) (curves.Point, error) {
	if len(input) != 2*bls12381Impl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var buffer [2 * bls12381Impl.FpBytes]byte
	copy(buffer[:], input)

	result := new(PointG2)
	compressedFlag := uint64((buffer[0] >> 7) & 1)
	infinityFlag := uint64((buffer[0] >> 6) & 1)
	sortFlag := uint64((buffer[0] >> 5) & 1)
	if compressedFlag != 1 {
		return nil, errs.NewFailed("compressed flag must be set")
	}
	if infinityFlag == 1 {
		if sortFlag == 1 {
			return nil, errs.NewFailed("infinity flag and sort flag are both set")
		}
		result.V.SetIdentity()
		return result, nil
	}

	buffer[0] &= 0x1f
	x1Bytes := buffer[:bls12381Impl.FpBytes]
	slices.Reverse(x1Bytes)
	x0Bytes := buffer[bls12381Impl.FpBytes : 2*bls12381Impl.FpBytes]
	slices.Reverse(x0Bytes)

	var x, y, yNeg bls12381Impl.Fp2
	if ok := x.U1.SetBytes(x1Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}
	if ok := x.U0.SetBytes(x0Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}

	// Recover a y-coordinate given x by y = sqrt(x^3 + 4)
	pp := new(PointG2)
	if wasSquare := pp.V.SetFromAffineX(&x); wasSquare != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}
	pp.V.ToAffine(&x, &y)
	yNeg.Neg(&pp.V.Y)
	pp.V.Y.Select(isNegative(&y)^sortFlag, &pp.V.Y, &yNeg)

	if !pp.IsInPrimeSubGroup() {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}
	return pp, nil
}

func (*PointG2) FromAffineUncompressed(input []byte) (curves.Point, error) {
	if len(input) != 4*bls12381Impl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var buffer [4 * bls12381Impl.FpBytes]byte
	copy(buffer[:], input)
	pp := new(PointG2)

	infinityFlag := uint64((input[0] >> 6) & 1)
	if infinityFlag == 1 {
		pp.V.SetIdentity()
		return pp, nil
	}

	// Mask away top bits
	buffer[0] &= 0x1f
	x1Bytes := buffer[:bls12381Impl.FpBytes]
	slices.Reverse(x1Bytes)
	x0Bytes := buffer[bls12381Impl.FpBytes : 2*bls12381Impl.FpBytes]
	slices.Reverse(x0Bytes)
	y1Bytes := buffer[2*bls12381Impl.FpBytes : 3*bls12381Impl.FpBytes]
	slices.Reverse(y1Bytes)
	y0Bytes := buffer[3*bls12381Impl.FpBytes:]
	slices.Reverse(y0Bytes)

	var x, y bls12381Impl.Fp2
	if ok := x.U1.SetBytes(x1Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}
	if ok := x.U0.SetBytes(x0Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}
	if ok := y.U1.SetBytes(y1Bytes); ok != 1 {
		return nil, errs.NewFailed("y is not an Fp2")
	}
	if ok := y.U0.SetBytes(y0Bytes); ok != 1 {
		return nil, errs.NewFailed("y is not an Fp2")
	}
	if valid := pp.V.SetAffine(&x, &y); valid != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}
	if !pp.IsInPrimeSubGroup() {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}

	return pp, nil
}

func (p *PointG2) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *PointG2) UnmarshalBinary(input []byte) error {
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
	ppt, ok := pt.(*PointG2)
	if !ok {
		return errs.NewType("invalid point")
	}
	p.V.Set(&ppt.V)
	return nil
}

func (p *PointG2) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *PointG2) UnmarshalJSON(input []byte) error {
	pt, err := curvesImpl.UnmarshalJson(p.Curve().Name(), p.FromAffineCompressed, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	P, ok := pt.(*PointG2)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V.Set(&P.V)
	return nil
}

func (p *PointG2) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}

func isNegative(v *bls12381Impl.Fp2) uint64 {
	c1Neg := fieldsImpl.IsNegative(&v.U1)
	c0Neg := fieldsImpl.IsNegative(&v.U0)
	c1Zero := v.U1.IsZero()

	return c1Neg | (c1Zero & c0Neg)
}
