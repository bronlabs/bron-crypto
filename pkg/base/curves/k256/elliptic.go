package k256

import (
	"crypto/elliptic"
	"math/big"
	"slices"

	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
)

var (
	ellipticK256Params = &elliptic.CurveParams{
		P:       mustSetBigIntString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
		N:       mustSetBigIntString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
		B:       mustSetBigIntString("0000000000000000000000000000000000000000000000000000000000000007"),
		Gx:      mustSetBigIntString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
		Gy:      mustSetBigIntString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
		BitSize: k256Impl.FpBits,
		Name:    CurveName,
	}
	ellipticK256Instance = &ellipticK256{}
)

type ellipticK256 struct {
}

// Params returns the curve parameters.
func (c *ellipticK256) Params() *elliptic.CurveParams {
	return ellipticK256Params
}

// IsOnCurve reports whether the point is on the curve.
func (c *ellipticK256) IsOnCurve(x, y *big.Int) bool {
	// IsOnCurve is documented to reject (0, 0), the conventional point at infinity.
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	_, err := fromAffine(x, y)
	return err != nil
}

// Add sets the receiver to lhs + rhs.
func (c *ellipticK256) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
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

// Double sets the receiver to 2*x.
func (c *ellipticK256) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p, err := fromAffine(x1, y1)
	if err != nil {
		panic("Double was called on an invalid point")
	}
	return toAffine(p.Double())
}

// ScalarMult multiplies a point by a scalar.
func (c *ellipticK256) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
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

// ScalarBaseMult multiplies the generator by a scalar.
func (c *ellipticK256) ScalarBaseMult(k []byte) (x, y *big.Int) {
	s, err := NewScalarField().FromWideBytes(k)
	if err != nil {
		panic("ScalarMult was called with an invalid scalar")
	}
	return toAffine(NewCurve().ScalarBaseMul(s))
}

func mustSetBigIntString(s string) *big.Int {
	bi, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("cannot set Int string")
	}
	return bi
}

func fromAffine(x *big.Int, y *big.Int) (*Point, error) {
	var xBytes, yBytes [32]byte
	x.FillBytes(xBytes[:])
	y.FillBytes(yBytes[:])
	return NewCurve().FromUncompressed(slices.Concat([]byte{0x04}, xBytes[:], yBytes[:]))
}

func toAffine(p *Point) (*big.Int, *big.Int) {
	if p.IsZero() {
		return new(big.Int), new(big.Int)
	}
	x, _ := p.AffineX()
	y, _ := p.AffineY()
	return x.Cardinal().Big(), y.Cardinal().Big()
}
