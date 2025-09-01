package bls12381

import (
	"crypto/elliptic"
	"math/big"

	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var (
	ellipticBls12381G1Params = &elliptic.CurveParams{
		P:       mustSetBigIntString("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16),
		N:       mustSetBigIntString("73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001", 16),
		B:       mustSetBigIntString("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004", 16),
		Gx:      mustSetBigIntString("17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB", 16),
		Gy:      mustSetBigIntString("08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1", 16),
		BitSize: bls12381Impl.FpBits,
		Name:    CurveNameG1,
	}
	ellipticBls12381g1Instance = &ellipticBls12381g1{}
)

type ellipticBls12381g1 struct {
}

func (c *ellipticBls12381g1) Params() *elliptic.CurveParams {
	return ellipticBls12381G1Params
}

func (c *ellipticBls12381g1) IsOnCurve(x, y *big.Int) bool {
	// IsOnCurve is documented to reject (0, 0), the conventional point at infinity.
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	_, err := fromAffine(x, y)
	return err != nil
}

func (c *ellipticBls12381g1) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	p1, err := fromAffine(x1, y1)
	if err != nil {
		panic("Add was called on an invalid point")
	}
	p2, err := fromAffine(x2, y2)
	if err != nil {
		panic("Add was called on an invalid point")
	}
	return toAffine(p1.Add(p2))
}

func (c *ellipticBls12381g1) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p, err := fromAffine(x1, y1)
	if err != nil {
		panic("Double was called on an invalid point")
	}
	return toAffine(p.Double())
}

func (c *ellipticBls12381g1) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	p, err := fromAffine(x1, y1)
	if err != nil {
		panic("ScalarMult was called on an invalid point")
	}
	s, err := NewScalarField().FromWideBytes(k)
	if err != nil {
		panic("ScalarMult was called with an invalid scalar")
	}

	return toAffine(p.ScalarMul(s))
}

func (c *ellipticBls12381g1) ScalarBaseMult(k []byte) (x, y *big.Int) {
	s, err := NewScalarField().FromWideBytes(k)
	if err != nil {
		panic("ScalarMult was called with an invalid scalar")
	}
	return toAffine(NewG1().ScalarBaseMul(s))
}

func mustSetBigIntString(s string, base int) *big.Int {
	bi, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("cannot set Int string")
	}
	return bi
}

func fromAffine(x *big.Int, y *big.Int) (*PointG1, error) {
	if x.Sign() == 0 && y.Sign() == 0 {
		return NewG1().Zero(), nil
	}

	var xBytes, yBytes [bls12381Impl.FpBytes]byte
	x.FillBytes(xBytes[:])
	y.FillBytes(yBytes[:])

	xFp, err := NewG1BaseField().FromBytes(xBytes[:])
	if err != nil {
		return nil, errs.WrapCoordinates(err, "invalid x")
	}
	yFp, err := NewG1BaseField().FromBytes(yBytes[:])
	if err != nil {
		return nil, errs.WrapCoordinates(err, "invalid y")
	}

	var p PointG1
	ok := p.V.SetAffine(&xFp.V, &yFp.V)
	if ok != 1 {
		return nil, errs.NewFailed("invalid point")
	}

	return &p, nil
}

func toAffine(p *PointG1) (*big.Int, *big.Int) {
	if p.IsZero() {
		return new(big.Int), new(big.Int)
	}
	x, _ := p.AffineX()
	y, _ := p.AffineY()
	return x.Cardinal().Big(), y.Cardinal().Big()
}
