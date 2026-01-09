package pasta

import (
	"crypto/elliptic"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

var (
	ellipticPallasParams = &elliptic.CurveParams{
		P:       mustSetBigIntString("40000000000000000000000000000000224698fc094cf91b992d30ed00000001"),
		N:       mustSetBigIntString("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001"),
		B:       mustSetBigIntString("0000000000000000000000000000000000000000000000000000000000000005"),
		Gx:      mustSetBigIntString("40000000000000000000000000000000224698fc094cf91b992d30ed00000000"),
		Gy:      mustSetBigIntString("0000000000000000000000000000000000000000000000000000000000000002"),
		BitSize: pastaImpl.FpBits,
		Name:    PallasName,
	}
	ellipticPallasInstance = &ellipticPallas{}

	ellipticVestaParams = &elliptic.CurveParams{
		P:       mustSetBigIntString("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001"),
		N:       mustSetBigIntString("40000000000000000000000000000000224698fc094cf91b992d30ed00000001"),
		B:       mustSetBigIntString("0000000000000000000000000000000000000000000000000000000000000005"),
		Gx:      mustSetBigIntString("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000"),
		Gy:      mustSetBigIntString("0000000000000000000000000000000000000000000000000000000000000002"),
		BitSize: pastaImpl.FqBits,
		Name:    VestaName,
	}
	ellipticVestaInstance = &ellipticVesta{}
)

type ellipticPallas struct {
}

// Params returns the curve parameters.
func (c *ellipticPallas) Params() *elliptic.CurveParams {
	return ellipticPallasParams
}

// IsOnCurve reports whether the point is on the curve.
func (c *ellipticPallas) IsOnCurve(x, y *big.Int) bool {
	// IsOnCurve is documented to reject (0, 0), the conventional point at infinity.
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	_, err := fromPallasAffine(x, y)
	return err != nil
}

// Add sets the receiver to lhs + rhs.
func (c *ellipticPallas) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	p1, err := fromPallasAffine(x1, y1)
	if err != nil {
		panic("Add was called on an invalid point")
	}
	p2, err := fromPallasAffine(x2, y2)
	if err != nil {
		panic("Add was called on an invalid point")
	}
	return toPallasAffine(p1.Add(p2))
}

// Double sets the receiver to 2*x.
func (c *ellipticPallas) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p, err := fromPallasAffine(x1, y1)
	if err != nil {
		panic("Double was called on an invalid point")
	}
	return toPallasAffine(p.Double())
}

// ScalarMult multiplies a point by a scalar.
func (c *ellipticPallas) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	p, err := fromPallasAffine(x1, y1)
	if err != nil {
		panic("ScalarMult was called on an invalid point")
	}
	s, err := NewPallasScalarField().FromWideBytes(k)
	if err != nil {
		panic("ScalarMult was called with an invalid scalar")
	}

	return toPallasAffine(p.ScalarMul(s))
}

// ScalarBaseMult multiplies the generator by a scalar.
func (c *ellipticPallas) ScalarBaseMult(k []byte) (x, y *big.Int) {
	s, err := NewPallasScalarField().FromWideBytes(k)
	if err != nil {
		panic("ScalarMult was called with an invalid scalar")
	}
	return toPallasAffine(NewPallasCurve().ScalarBaseMul(s))
}

type ellipticVesta struct {
}

// Params returns the curve parameters.
func (c *ellipticVesta) Params() *elliptic.CurveParams {
	return ellipticVestaParams
}

// IsOnCurve reports whether the point is on the curve.
func (c *ellipticVesta) IsOnCurve(x, y *big.Int) bool {
	// IsOnCurve is documented to reject (0, 0), the conventional point at infinity.
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	_, err := fromVestaAffine(x, y)
	return err != nil
}

// Add sets the receiver to lhs + rhs.
func (c *ellipticVesta) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	p1, err := fromVestaAffine(x1, y1)
	if err != nil {
		panic("Add was called on an invalid point")
	}
	p2, err := fromVestaAffine(x2, y2)
	if err != nil {
		panic("Add was called on an invalid point")
	}
	return toVestaAffine(p1.Add(p2))
}

// Double sets the receiver to 2*x.
func (c *ellipticVesta) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p, err := fromVestaAffine(x1, y1)
	if err != nil {
		panic("Double was called on an invalid point")
	}
	return toVestaAffine(p.Double())
}

// ScalarMult multiplies a point by a scalar.
func (c *ellipticVesta) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	p, err := fromVestaAffine(x1, y1)
	if err != nil {
		panic("ScalarMult was called on an invalid point")
	}
	s, err := NewVestaScalarField().FromWideBytes(k)
	if err != nil {
		panic("ScalarMult was called with an invalid scalar")
	}

	return toVestaAffine(p.ScalarMul(s))
}

// ScalarBaseMult multiplies the generator by a scalar.
func (c *ellipticVesta) ScalarBaseMult(k []byte) (x, y *big.Int) {
	s, err := NewVestaScalarField().FromWideBytes(k)
	if err != nil {
		panic("ScalarMult was called with an invalid scalar")
	}
	return toVestaAffine(NewVestaCurve().ScalarBaseMul(s))
}

func fromPallasAffine(x *big.Int, y *big.Int) (*PallasPoint, error) {
	if x.Sign() == 0 && y.Sign() == 0 {
		return NewPallasCurve().Zero(), nil
	}

	var xBytes, yBytes [pastaImpl.FpBytes]byte
	x.FillBytes(xBytes[:])
	y.FillBytes(yBytes[:])

	xFp, err := NewPallasBaseField().FromBytes(xBytes[:])
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid x")
	}
	yFp, err := NewPallasBaseField().FromBytes(yBytes[:])
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid y")
	}

	var p PallasPoint
	ok := p.V.SetAffine(&xFp.V, &yFp.V)
	if ok != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid point")
	}

	return &p, nil
}

func toPallasAffine(p *PallasPoint) (*big.Int, *big.Int) {
	if p.IsZero() {
		return new(big.Int), new(big.Int)
	}
	x, _ := p.AffineX()
	y, _ := p.AffineY()
	return x.Cardinal().Big(), y.Cardinal().Big()
}

func fromVestaAffine(x *big.Int, y *big.Int) (*VestaPoint, error) {
	if x.Sign() == 0 && y.Sign() == 0 {
		return NewVestaCurve().Zero(), nil
	}

	var xBytes, yBytes [pastaImpl.FqBytes]byte
	x.FillBytes(xBytes[:])
	y.FillBytes(yBytes[:])

	xFp, err := NewVestaBaseField().FromBytes(xBytes[:])
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid x")
	}
	yFp, err := NewVestaBaseField().FromBytes(yBytes[:])
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid y")
	}

	var p VestaPoint
	ok := p.V.SetAffine(&xFp.V, &yFp.V)
	if ok != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid point")
	}

	return &p, nil
}

func toVestaAffine(p *VestaPoint) (*big.Int, *big.Int) {
	if p.IsZero() {
		return new(big.Int), new(big.Int)
	}
	x, _ := p.AffineX()
	y, _ := p.AffineY()
	return x.Cardinal().Big(), y.Cardinal().Big()
}

func mustSetBigIntString(s string) *big.Int {
	bi, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("cannot set Int string")
	}
	return bi
}
