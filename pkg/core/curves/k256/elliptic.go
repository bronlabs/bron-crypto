package k256

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	"github.com/btcsuite/btcd/btcec"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	secp256k1 "github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

var (
	oldK256Initonce sync.Once
	oldK256         Koblitz256
)

type Koblitz256 struct {
	*elliptic.CurveParams
}

func oldK256InitAll() {
	curve := btcec.S256()
	oldK256.CurveParams = new(elliptic.CurveParams)
	oldK256.P = curve.P
	oldK256.N = curve.N
	oldK256.Gx = curve.Gx
	oldK256.Gy = curve.Gy
	oldK256.B = curve.B
	oldK256.BitSize = curve.BitSize
	oldK256.Name = Name
}

func NewElliptic() *Koblitz256 {
	oldK256Initonce.Do(oldK256InitAll)
	return &oldK256
}

func (curve *Koblitz256) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (*Koblitz256) IsOnCurve(x, y *big.Int) bool {
	_, err := secp256k1.PointNew().SetBigInt(x, y)
	return err == nil
}

func (*Koblitz256) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1, err := secp256k1.PointNew().SetBigInt(x1, y1)
	if err != nil {
		return nil, nil
	}
	p2, err := secp256k1.PointNew().SetBigInt(x2, y2)
	if err != nil {
		return nil, nil
	}
	return p1.Add(p1, p2).BigInt()
}

func (*Koblitz256) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p1, err := secp256k1.PointNew().SetBigInt(x1, y1)
	if err != nil {
		return nil, nil
	}
	return p1.Double(p1).BigInt()
}

func (*Koblitz256) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	p1, err := secp256k1.PointNew().SetBigInt(Bx, By)
	if err != nil {
		panic(errs.WrapDeserializationFailed(err, "set big int"))
	}
	if len(k) > 32 {
		panic("invalid scalar length")
	}
	var bytes_ [32]byte
	copy(bytes_[:], bitstring.ReverseBytes(k))
	s, err := fq.New().SetBytes(&bytes_)
	if err != nil {
		panic(errs.WrapDeserializationFailed(err, "set bytes"))
	}
	return p1.Mul(p1, s).BigInt()
}

func (*Koblitz256) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	if len(k) > 32 {
		panic("invalid scalar length")
	}
	var bytes_ [32]byte
	copy(bytes_[:], bitstring.ReverseBytes(k))
	s, err := fq.New().SetBytes(&bytes_)
	if err != nil {
		panic(errs.WrapDeserializationFailed(err, "set bytes"))
	}
	p1 := secp256k1.PointNew().Generator()
	return p1.Mul(p1, s).BigInt()
}
