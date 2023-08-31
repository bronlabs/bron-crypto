package bls12381

import (
	"bytes"
	"io"
	"reflect"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	bls12381impl "github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.PairingPoint = (*PointG1)(nil)

type PointG1 struct {
	Value *bls12381impl.G1

	_ helper_types.Incomparable
}

func (*PointG1) Curve() curves.Curve {
	return NewG1()
}

func (*PointG1) PairingCurve() curves.PairingCurve {
	return New()
}

func (*PointG1) PairingCurveName() string {
	return Name
}

func (p *PointG1) Random(reader io.Reader) curves.Point {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (*PointG1) Hash(inputs ...[]byte) curves.Point {
	domain := []byte("QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_")
	pt := new(bls12381impl.G1).Hash(impl.EllipticPointHasherSha256(), bytes.Join(inputs, nil), domain)
	return &PointG1{Value: pt}
}

func (*PointG1) HashWithDst(input []byte, dst string) curves.PairingPoint {
	pt := new(bls12381impl.G1).Hash(impl.EllipticPointHasherSha256(), input, []byte(dst))
	return &PointG1{Value: pt}
}

func (p *PointG1) IsTorsionFree() bool {
	return p.Value.InCorrectSubgroup() == 1
}

func (*PointG1) Identity() curves.Point {
	return &PointG1{
		Value: new(bls12381impl.G1).Identity(),
	}
}

func (p *PointG1) IsSmallOrder() bool {
	return !p.IsTorsionFree()
}

func (*PointG1) Generator() curves.Point {
	return &PointG1{
		Value: new(bls12381impl.G1).Generator(),
	}
}

func (p *PointG1) IsIdentity() bool {
	return p.Value.IsIdentity() == 1
}

func (p *PointG1) IsNegative() bool {
	// According to https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
	// This bit represents the sign of the `y` coordinate which is what we want
	return (p.Value.ToCompressed()[0]>>5)&1 == 1
}

func (p *PointG1) IsOnCurve() bool {
	return p.Value.IsOnCurve() == 1
}

func (p *PointG1) Double() curves.Point {
	return &PointG1{Value: new(bls12381impl.G1).Double(p.Value)}
}

func (*PointG1) Scalar() curves.Scalar {
	return &ScalarBls12381{
		Value:  bls12381impl.FqNew(),
		Point_: new(PointG1),
	}
}

func (p *PointG1) Neg() curves.Point {
	return &PointG1{Value: new(bls12381impl.G1).Neg(p.Value)}
}

func (p *PointG1) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG1)
	if ok {
		return &PointG1{Value: new(bls12381impl.G1).Add(p.Value, r.Value)}
	} else {
		panic("rhs is not PointBls12381G1")
	}
}

func (p *PointG1) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG1)
	if ok {
		return &PointG1{Value: new(bls12381impl.G1).Sub(p.Value, r.Value)}
	} else {
		panic("rhs is not PointBls12381G1")
	}
}

func (p *PointG1) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		return &PointG1{Value: new(bls12381impl.G1).Mul(p.Value, r.Value)}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (p *PointG1) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*PointG1)
	if ok {
		return p.Value.Equal(r.Value) == 1
	} else {
		return false
	}
}

func (p *PointG1) Clone() curves.Point {
	return &PointG1{Value: new(bls12381impl.G1).Set(p.Value)}
}

func (p *PointG1) ClearCofactor() curves.Point {
	return &PointG1{Value: new(bls12381impl.G1).ClearCofactor(p.Value)}
}

func (*PointG1) Set(x, y *saferith.Nat) (curves.Point, error) {
	value, err := new(bls12381impl.G1).SetNat(x, y)
	if err != nil {
		return nil, errs.NewInvalidCoordinates("invalid coordinates")
	}
	return &PointG1{Value: value}, nil
}

func (p *PointG1) ToAffineCompressed() []byte {
	out := p.Value.ToCompressed()
	return out[:]
}

func (p *PointG1) ToAffineUncompressed() []byte {
	out := p.Value.ToUncompressed()
	return out[:]
}

func (*PointG1) FromAffineCompressed(input []byte) (curves.Point, error) {
	var b [bls12381impl.FieldBytes]byte
	copy(b[:], input)
	value, err := new(bls12381impl.G1).FromCompressed(&b)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't construct G1 point from affine compressed")
	}
	return &PointG1{Value: value}, nil
}

func (*PointG1) FromAffineUncompressed(input []byte) (curves.Point, error) {
	var b [96]byte
	copy(b[:], input)
	value, err := new(bls12381impl.G1).FromUncompressed(&b)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't construct G1 point from affine uncompressed")
	}
	return &PointG1{Value: value}, nil
}

func (*PointG1) CurveName() string {
	return G1Name
}

func multiScalarMultBls12381G1(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]*bls12381impl.G1, len(points))
	nScalars := make([]*impl.Field, len(scalars))
	for i, pt := range points {
		pp, ok := pt.(*PointG1)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointBls12381G1", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = pp.Value
	}
	for i, sc := range scalars {
		s, ok := sc.(*ScalarBls12381)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarBls12381", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.Value
	}
	value, err := new(bls12381impl.G1).SumOfProducts(nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multi scalar multiplication failed")
	}
	return &PointG1{Value: value}, nil
}

func (*PointG1) OtherGroup() curves.PairingPoint {
	return new(PointG2).Identity().(curves.PairingPoint)
}

func (p *PointG1) Pairing(rhs curves.PairingPoint) curves.Scalar {
	pt, ok := rhs.(*PointG2)
	if !ok {
		panic("rhs is not PointBls12381G2")
	}
	e := new(bls12381impl.Engine)
	e.AddPair(p.Value, pt.Value)

	value := e.Result()

	return &ScalarGt{Value: value}
}

func (p *PointG1) X() curves.FieldElement {
	return &FieldElementG1{
		v: p.Value.GetX(),
	}
}

func (p *PointG1) Y() curves.FieldElement {
	return &FieldElementG1{
		v: p.Value.GetY(),
	}
}

func (p *PointG1) ProjectiveX() curves.FieldElement {
	return &FieldElementG1{
		v: &p.Value.X,
	}
}

func (p *PointG1) ProjectiveY() curves.FieldElement {
	return &FieldElementG1{
		v: &p.Value.Y,
	}
}

func (p *PointG1) ProjectiveZ() curves.FieldElement {
	return &FieldElementG1{
		v: &p.Value.Z,
	}
}

func (*PointG1) Modulus() *saferith.Modulus {
	return p
}

func (p *PointG1) MarshalBinary() ([]byte, error) {
	result, err := internal.PointMarshalBinary(p)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't marshal to binary")
	}
	return result, nil
}

func (p *PointG1) UnmarshalBinary(input []byte) error {
	pt, err := internal.PointUnmarshalBinary(NewG1(), input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ppt, ok := pt.(*PointG1)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointG1) MarshalText() ([]byte, error) {
	result, err := internal.PointMarshalText(p)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't marshal to text")
	}
	return result, nil
}

func (p *PointG1) UnmarshalText(input []byte) error {
	pt, err := internal.PointUnmarshalText(NewG1(), input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ppt, ok := pt.(*PointG1)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointG1) MarshalJSON() ([]byte, error) {
	result, err := internal.PointMarshalJson(p)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't marshal to json")
	}
	return result, nil
}

func (p *PointG1) UnmarshalJSON(input []byte) error {
	pt, err := internal.NewPointFromJSON(NewG1(), input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not extract a point from json")
	}
	P, ok := pt.(*PointG1)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.Value = P.Value
	return nil
}
