package bls12381

import (
	"encoding"
	"encoding/binary"
	"encoding/json"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	curvesImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var _ curves.PairingPoint = (*PointG1)(nil)
var _ curves.ProjectiveCurveCoordinates = (*PointG1)(nil)
var _ encoding.BinaryMarshaler = (*PointG1)(nil)
var _ encoding.BinaryUnmarshaler = (*PointG1)(nil)
var _ json.Unmarshaler = (*PointG1)(nil)

type PointG1 struct {
	V bls12381Impl.G1Point

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
	orderBytes := g1SubGroupOrder.Bytes()
	slices.Reverse(orderBytes)
	var pp bls12381Impl.G1Point
	pointsImpl.ScalarMul[*bls12381Impl.Fp](&pp, &p.V, orderBytes)
	return pp.IsIdentity() == 1
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
	rhsp, ok := rhs.(*PointG1)
	if !ok {
		return false
	}

	return p.V.Equals(&rhsp.V) == 1
}

func (p *PointG1) Clone() curves.Point {
	clone := new(PointG1)
	clone.V.Set(&p.V)
	return clone
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
	if !ok {
		panic("rhs is not PointBls12381G1")
	}

	result := new(PointG1)
	result.V.Add(&p.V, &r.V)
	return result
}

func (p *PointG1) ApplyAdd(q algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], n *saferith.Nat) curves.Point {
	return p.Add(q.Unwrap().ScalarMul(NewScalarFieldG1().Element().SetNat(n)))
}

func (p *PointG1) Double() curves.Point {
	result := new(PointG1)
	result.V.Double(&p.V)
	return result
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
	result := new(PointG1)
	result.V.Neg(&p.V)
	return result
}

func (p *PointG1) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.Curve, curves.Point]) bool {
	return p.Add(of).IsAdditiveIdentity()
}

func (p *PointG1) Sub(rhs algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG1)
	if !ok {
		panic("rhs is not PointBls12381G1")
	}

	result := new(PointG1)
	result.V.Sub(&p.V, &r.V)
	return result
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
	if !ok {
		panic("rhs is not ScalarBls12381")
	}

	result := new(PointG1)
	pointsImpl.ScalarMul[*bls12381Impl.Fp](&result.V, &p.V, r.V.Bytes())
	return result
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
	var x, y bls12381Impl.Fp
	p.V.ToAffine(&x, &y)
	return fieldsImpl.IsNegative(&y) == 1
}

func (p *PointG1) IsSmallOrder() bool {
	return p.ClearCofactor().IsAdditiveIdentity()
}

func (p *PointG1) ClearCofactor() curves.Point {
	hEffBytes := g1HEffective.Bytes()
	slices.Reverse(hEffBytes)

	result := new(PointG1)
	pointsImpl.ScalarMul[*bls12381Impl.Fp](&result.V, &p.V, hEffBytes)
	return result
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
	e := new(bls12381Impl.Engine)
	e.AddPair(&p.V, &rhs.(*PointG2).V)
	value := e.Result()

	result := new(GtMember)
	result.V.Set(value)
	return result
}

// === Coordinate Interface Methods.

func (p *PointG1) AffineCoordinates() []curves.BaseFieldElement {
	x := new(BaseFieldElementG1)
	y := new(BaseFieldElementG1)
	ok := p.V.ToAffine(&x.V, &y.V)
	if ok != 1 {
		return []curves.BaseFieldElement{
			p.Curve().BaseField().AdditiveIdentity(),
			p.Curve().BaseField().AdditiveIdentity(),
		}
	}

	return []curves.BaseFieldElement{x, y}
}

func (p *PointG1) AffineX() curves.BaseFieldElement {
	return p.AffineCoordinates()[0]
}

func (p *PointG1) AffineY() curves.BaseFieldElement {
	return p.AffineCoordinates()[1]
}

func (p *PointG1) ProjectiveX() curves.BaseFieldElement {
	x := new(BaseFieldElementG1)
	x.V.Set(&p.V.X)
	return x
}

func (p *PointG1) ProjectiveY() curves.BaseFieldElement {
	y := new(BaseFieldElementG1)
	y.V.Set(&p.V.Y)
	return y
}

func (p *PointG1) ProjectiveZ() curves.BaseFieldElement {
	z := new(BaseFieldElementG1)
	z.V.Set(&p.V.Z)
	return z
}

// === Serialisation.

func (p *PointG1) ToAffineCompressed() []byte {
	var x, y bls12381Impl.Fp
	x.SetZero()
	y.SetZero()
	p.V.ToAffine(&x, &y)

	bitC := uint64(1)
	bitI := p.V.IsIdentity()
	bitS := fieldsImpl.IsNegative(&y) & (bitI ^ 1)
	m := byte((bitC << 7) | (bitI << 6) | (bitS << 5))

	xBytes := x.Bytes()
	slices.Reverse(xBytes)
	xBytes[0] |= m
	return xBytes
}

func (p *PointG1) ToAffineUncompressed() []byte {
	var x, y bls12381Impl.Fp
	x.SetZero()
	y.SetZero()
	p.V.ToAffine(&x, &y)

	bitC := uint64(0)
	bitI := p.V.IsIdentity()
	bitS := uint64(0)
	m := byte((bitC << 7) | (bitI << 6) | (bitS << 5))

	xBytes := x.Bytes()
	slices.Reverse(xBytes)
	yBytes := y.Bytes()
	slices.Reverse(yBytes)

	result := slices.Concat(xBytes, yBytes)
	result[0] |= m
	return result
}

func (*PointG1) FromAffineCompressed(input []byte) (curves.Point, error) {
	if len(input) != bls12381Impl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var xFp, yFp, yNegFp bls12381Impl.Fp
	var xBytes [bls12381Impl.FpBytes]byte
	pp := new(PointG1)
	compressedFlag := uint64((input[0] >> 7) & 1)
	infinityFlag := uint64((input[0] >> 6) & 1)
	sortFlag := uint64((input[0] >> 5) & 1)

	if compressedFlag != 1 {
		return nil, errs.NewFailed("compressed flag must be set")
	}

	if infinityFlag == 1 {
		if sortFlag == 1 {
			return nil, errs.NewFailed("infinity flag and sort flag are both set")
		}
		pp.V.SetIdentity()
		return pp, nil
	}

	copy(xBytes[:], input)
	// Mask away the flag bits
	xBytes[0] &= 0x1f
	slices.Reverse(xBytes[:])
	if valid := xFp.SetBytes(xBytes[:]); valid != 1 {
		return nil, errs.NewFailed("invalid bytes - not in field")
	}

	if wasSquare := pp.V.SetFromAffineX(&xFp); wasSquare != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}
	if ok := pp.V.ToAffine(&xFp, &yFp); ok != 1 {
		panic("this should never happen")
	}

	yNegFp.Neg(&pp.V.Y)
	pp.V.Y.Select(fieldsImpl.IsNegative(&yFp)^sortFlag, &pp.V.Y, &yNegFp)

	if !pp.IsInPrimeSubGroup() {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}

	return pp, nil
}

func (*PointG1) FromAffineUncompressed(input []byte) (curves.Point, error) {
	if len(input) != 2*bls12381Impl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var xFp, yFp bls12381Impl.Fp
	var t [2 * bls12381Impl.FpBytes]byte
	pp := new(PointG1)
	infinityFlag := uint64((input[0] >> 6) & 1)

	if infinityFlag == 1 {
		pp.V.SetIdentity()
		return pp, nil
	}

	copy(t[:], input)
	// Mask away top bits
	t[0] &= 0x1f
	xBytes := t[:bls12381Impl.FpBytes]
	slices.Reverse(xBytes)
	yBytes := t[bls12381Impl.FpBytes:]
	slices.Reverse(yBytes)

	if valid := xFp.SetBytes(xBytes); valid != 1 {
		return nil, errs.NewFailed("invalid bytes - x not in field")
	}
	if valid := yFp.SetBytes(yBytes); valid != 1 {
		return nil, errs.NewFailed("invalid bytes - y not in field")
	}
	if valid := pp.V.SetAffine(&xFp, &yFp); valid != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}
	if !pp.IsInPrimeSubGroup() {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}

	return pp, nil
}

func (p *PointG1) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(p.Curve().Name(), p.ToAffineCompressed)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (p *PointG1) UnmarshalBinary(input []byte) error {
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
	ppt, ok := pt.(*PointG1)
	if !ok {
		return errs.NewType("invalid point")
	}
	p.V.Set(&ppt.V)
	return nil
}

func (p *PointG1) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(p.Curve().Name(), p.ToAffineCompressed)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *PointG1) UnmarshalJSON(input []byte) error {
	pt, err := curvesImpl.UnmarshalJson(p.Curve().Name(), p.FromAffineCompressed, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	P, ok := pt.(*PointG1)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.V.Set(&P.V)
	return nil
}

// === Hashable.

func (p *PointG1) HashCode() uint64 {
	return binary.BigEndian.Uint64(p.ToAffineCompressed())
}
