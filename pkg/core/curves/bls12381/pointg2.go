package bls12381

import (
	"bytes"
	"io"
	"math/big"
	"reflect"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	bls12381impl "github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ (curves.PairingPoint) = (*PointG2)(nil)

type PointG2 struct {
	Value *bls12381impl.G2

	_ helper_types.Incomparable
}

func (PointG2) Curve() (curves.Curve, error) {
	return NewG2(), nil
}

func (PointG2) PairingCurve() curves.PairingCurve {
	return New()
}

func (PointG2) PairingCurveName() string {
	return Name
}

func (p *PointG2) Random(reader io.Reader) curves.Point {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (*PointG2) Hash(inputs ...[]byte) curves.Point {
	domain := []byte("BLS12381G2_XMD:SHA-256_SSWU_RO_")
	pt := new(bls12381impl.G2).Hash(impl.EllipticPointHasherSha256(), bytes.Join(inputs, nil), domain)
	return &PointG2{Value: pt}
}

func (*PointG2) Identity() curves.Point {
	return &PointG2{
		Value: new(bls12381impl.G2).Identity(),
	}
}

func (*PointG2) Generator() curves.Point {
	return &PointG2{
		Value: new(bls12381impl.G2).Generator(),
	}
}

func (p *PointG2) IsIdentity() bool {
	return p.Value.IsIdentity() == 1
}

func (p *PointG2) IsNegative() bool {
	// According to https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
	// This bit represents the sign of the `y` coordinate which is what we want
	return (p.Value.ToCompressed()[0]>>5)&1 == 1
}

func (p *PointG2) IsOnCurve() bool {
	return p.Value.IsOnCurve() == 1
}

func (p *PointG2) Double() curves.Point {
	return &PointG2{Value: new(bls12381impl.G2).Double(p.Value)}
}

func (*PointG2) Scalar() curves.Scalar {
	return &Scalar{
		Value: bls12381impl.FqNew(),
		point: new(PointG2),
	}
}

func (p *PointG2) Neg() curves.Point {
	return &PointG2{Value: new(bls12381impl.G2).Neg(p.Value)}
}

func (p *PointG2) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG2)
	if ok {
		return &PointG2{Value: new(bls12381impl.G2).Add(p.Value, r.Value)}
	} else {
		panic("rhs is not PointBls12381G2")
	}
}

func (p *PointG2) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointG2)
	if ok {
		return &PointG2{Value: new(bls12381impl.G2).Sub(p.Value, r.Value)}
	} else {
		panic("rhs is not PointBls12381G2")
	}
}

func (p *PointG2) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		return &PointG2{Value: new(bls12381impl.G2).Mul(p.Value, r.Value)}
	} else {
		panic("rhs is not PointBls12381G2")
	}
}

func (p *PointG2) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*PointG2)
	if ok {
		return p.Value.Equal(r.Value) == 1
	} else {
		return false
	}
}

func (*PointG2) Set(x, y *big.Int) (curves.Point, error) {
	value, err := new(bls12381impl.G2).SetBigInt(x, y)
	if err != nil {
		return nil, errs.NewInvalidCoordinates("invalid coordinates")
	}
	return &PointG2{Value: value}, nil
}

func (p *PointG2) ToAffineCompressed() []byte {
	out := p.Value.ToCompressed()
	return out[:]
}

func (p *PointG2) ToAffineUncompressed() []byte {
	out := p.Value.ToUncompressed()
	return out[:]
}

func (*PointG2) FromAffineCompressed(input []byte) (curves.Point, error) {
	var b [bls12381impl.WideFieldBytes]byte
	copy(b[:], input)
	value, err := new(bls12381impl.G2).FromCompressed(&b)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "couldn't construct G2 from affine compressed")
	}
	return &PointG2{Value: value}, nil
}

func (*PointG2) FromAffineUncompressed(input []byte) (curves.Point, error) {
	var b [bls12381impl.DoubleWideFieldBytes]byte
	copy(b[:], input)
	value, err := new(bls12381impl.G2).FromUncompressed(&b)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "couldn't construct G2 from affine uncompressed")
	}
	return &PointG2{Value: value}, nil
}

func (*PointG2) CurveName() string {
	return G2Name
}

func MultiScalarMultBls12381G2(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]*bls12381impl.G2, len(points))
	nScalars := make([]*impl.Field, len(scalars))
	for i, pt := range points {
		pp, ok := pt.(*PointG2)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointBls12381G2", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = pp.Value
	}
	for i, sc := range scalars {
		s, ok := sc.(*Scalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarBls12381", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.Value
	}
	value, err := new(bls12381impl.G2).SumOfProducts(nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}
	return &PointG2{Value: value}, nil
}

func (*PointG2) OtherGroup() curves.PairingPoint {
	return new(PointG1).Identity().(curves.PairingPoint)
}

func (p *PointG2) Pairing(rhs curves.PairingPoint) curves.Scalar {
	pt, ok := rhs.(*PointG1)
	if !ok {
		return nil
	}
	e := new(bls12381impl.Engine)
	e.AddPair(pt.Value, p.Value)

	value := e.Result()

	return &ScalarGt{Value: value}
}

func (PointG2) X() curves.FieldElement {
	return nil
}

func (PointG2) Y() curves.FieldElement {
	return nil
}

// func (p *PointBls12381G2) X() *big.Int {
// 	x := p.Value.ToUncompressed()
// 	return new(big.Int).SetBytes(x[:bls12381impl.WideFieldBytes])
// }.

// func (p *PointBls12381G2) Y() *big.Int {
// 	y := p.Value.ToUncompressed()
// 	return new(big.Int).SetBytes(y[bls12381impl.WideFieldBytes:])
// }.

func (*PointG2) Modulus() *big.Int {
	return modulus
}

func (p *PointG2) MarshalBinary() ([]byte, error) {
	result, err := internal.PointMarshalBinary(p)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't marshal to binary")
	}
	return result, nil
}

func (p *PointG2) UnmarshalBinary(input []byte) error {
	pt, err := internal.PointUnmarshalBinary(NewG2(), input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointG2)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointG2) MarshalText() ([]byte, error) {
	result, err := internal.PointMarshalText(p)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't marshal to text")
	}
	return result, nil
}

func (p *PointG2) UnmarshalText(input []byte) error {
	pt, err := internal.PointUnmarshalText(NewG2(), input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointG2)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointG2) MarshalJSON() ([]byte, error) {
	result, err := internal.PointMarshalJson(p)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't marshal to json")
	}
	return result, nil
}

func (p *PointG2) UnmarshalJSON(input []byte) error {
	pt, err := internal.NewPointFromJSON(NewG2(), input)
	if err != nil {
		return errs.WrapFailed(err, "could not extract a point from json")
	}
	P, ok := pt.(*PointG2)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.Value = P.Value
	return nil
}
