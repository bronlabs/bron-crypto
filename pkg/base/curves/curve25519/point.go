package curve25519

import (
	"crypto/subtle"
	"io"

	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/curve25519"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Point = (*Point)(nil)

type Point struct {
	Value [32]byte

	_ types.Incomparable
}

func (p *Point) X() curves.FieldElement {
	return &FieldElement{v: p.Value}
}

func (*Point) Y() curves.FieldElement {
	//TODO implement me
	panic("implement me")
}

func (*Point) Random(prng io.Reader) curves.Point {
	//TODO implement me
	panic("implement me")
}

func (*Point) Hash(bytes ...[]byte) curves.Point {
	//TODO implement me
	panic("implement me")
}

func (*Point) Identity() curves.Point {
	return &Point{
		Value: [32]byte{
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
	}
}

func (*Point) Generator() curves.Point {
	var result [32]byte
	copy(result[:], curve25519.Basepoint)
	return &Point{
		Value: result,
	}
}

func (p *Point) IsIdentity() bool {
	return p.Equal(p.Identity())
}

func (*Point) IsNegative() bool {
	//TODO implement me
	panic("implement me")
}

func (*Point) IsOnCurve() bool {
	//TODO implement me
	panic("implement me")
}

func (*Point) Double() curves.Point {
	//TODO implement me
	panic("implement me")
}

func (*Point) Scalar() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Point) Neg() curves.Point {
	//TODO implement me
	panic("implement me")
}

func (*Point) ClearCofactor() curves.Point {
	//TODO implement me
	panic("implement me")
}

func (*Point) Clone() curves.Point {
	//TODO implement me
	panic("implement me")
}

func (*Point) Add(rhs curves.Point) curves.Point {
	//TODO implement me
	panic("implement me")
}

func (*Point) Sub(rhs curves.Point) curves.Point {
	//TODO implement me
	panic("implement me")
}

func (p *Point) Mul(rhs curves.Scalar) curves.Point {
	var ss []byte
	ss, err := curve25519.X25519(rhs.Bytes(), p.Value[:])
	if err != nil {
		panic(err)
	}
	var result [32]byte
	copy(result[:], ss)
	return &Point{Value: result}
}

func (p *Point) X25519(rhs curves.Scalar) curves.Point {
	var ss []byte
	ss, err := curve25519.X25519(rhs.Bytes(), p.Value[:])
	if err != nil {
		panic(err)
	}
	var result [32]byte
	copy(result[:], ss)
	return &Point{Value: result}
}

func (p *Point) Equal(rhs curves.Point) bool {
	return subtle.ConstantTimeCompare(p.Value[:], rhs.ToAffineCompressed()) == 1
}

func (*Point) Set(x, y *saferith.Nat) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (p *Point) ToAffineCompressed() []byte {
	return p.Value[:]
}

func (*Point) ToAffineUncompressed() []byte {
	//TODO implement me
	panic("implement me")
}

func (*Point) FromAffineCompressed(bytes []byte) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Point) FromAffineUncompressed(bytes []byte) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
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
		if subtle.ConstantTimeCompare(p.Value[:], testValue[:]) == 1 {
			panic("Invalid public key")
		}
	}
	return true
}

func (*Point) Curve() curves.Curve {
	return &curve25519Instance
}

func (*Point) CurveName() string {
	return Name
}

func (p *Point) MarshalBinary() ([]byte, error) {
	return internal.PointMarshalBinary(p)
}

func (p *Point) UnmarshalBinary(input []byte) error {
	pt, err := internal.PointUnmarshalBinary(&curve25519Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal binary")
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *Point) MarshalText() ([]byte, error) {
	return internal.PointMarshalText(p)
}

func (p *Point) UnmarshalText(input []byte) error {
	pt, err := internal.PointUnmarshalText(&curve25519Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal text")
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *Point) MarshalJSON() ([]byte, error) {
	return internal.PointMarshalJson(p)
}

func (p *Point) UnmarshalJSON(input []byte) error {
	pt, err := internal.NewPointFromJSON(&curve25519Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	P, ok := pt.(*Point)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.Value = P.Value
	return nil
}
