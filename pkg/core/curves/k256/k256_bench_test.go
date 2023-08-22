package k256_test

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"

	mod "github.com/copperexchange/knox-primitives/pkg/core"
	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

func BenchmarkK256(b *testing.B) {
	// 1000 points
	b.Run("1000 point add - btcec", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			points := make([]*BenchPoint, 1000)
			for i := range points {
				points[i] = points[i].Random(crand.Reader).(*BenchPoint)
			}
			acc := new(BenchPoint).Identity()
			b.StartTimer()
			for _, pt := range points {
				acc = acc.Add(pt)
			}
		}
	})
	b.Run("1000 point add - ct k256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			curve := k256.New()
			points := make([]*k256.Point, 1000)
			for i := range points {
				points[i] = curve.Identity().Random(crand.Reader).(*k256.Point)
			}
			acc := curve.Identity()
			b.StartTimer()
			for _, pt := range points {
				acc = acc.Add(pt)
			}
		}
	})
	b.Run("1000 point double - btcec", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			acc := new(BenchPoint).Generator()
			b.StartTimer()
			for i := 0; i < 1000; i++ {
				acc = acc.Double()
			}
		}
	})
	b.Run("1000 point double - ct k256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			acc := new(k256.Point).Generator()
			b.StartTimer()
			for i := 0; i < 1000; i++ {
				acc = acc.Double()
			}
		}
	})
	b.Run("1000 point multiply - btcec", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*BenchScalar, 1000)
			for i := range scalars {
				s := new(BenchScalar).Random(crand.Reader)
				scalars[i] = s.(*BenchScalar)
			}
			acc := new(BenchPoint).Generator().Mul(new(BenchScalar).New(2))
			b.StartTimer()
			for _, sc := range scalars {
				acc = acc.Mul(sc)
			}
		}
	})
	b.Run("1000 point multiply - ct k256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*k256.Scalar, 1000)
			for i := range scalars {
				s := new(k256.Scalar).Random(crand.Reader)
				scalars[i] = s.(*k256.Scalar)
			}
			acc := new(k256.Point).Generator()
			b.StartTimer()
			for _, sc := range scalars {
				acc = acc.Mul(sc)
			}
		}
	})
	b.Run("1000 scalar invert - btcec", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*BenchScalar, 1000)
			for i := range scalars {
				s := new(BenchScalar).Random(crand.Reader)
				scalars[i] = s.(*BenchScalar)
			}
			b.StartTimer()
			for _, sc := range scalars {
				_, _ = sc.Invert()
			}
		}
	})
	b.Run("1000 scalar invert - ct k256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*k256.Scalar, 1000)
			for i := range scalars {
				s := new(k256.Scalar).Random(crand.Reader)
				scalars[i] = s.(*k256.Scalar)
			}
			b.StartTimer()
			for _, sc := range scalars {
				_, _ = sc.Invert()
			}
		}
	})
	b.Run("1000 scalar sqrt - btcec", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*BenchScalar, 1000)
			for i := range scalars {
				s := new(BenchScalar).Random(crand.Reader)
				scalars[i] = s.(*BenchScalar)
			}
			b.StartTimer()
			for _, sc := range scalars {
				_, _ = sc.Sqrt()
			}
		}
	})
	b.Run("1000 scalar sqrt - ct k256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*k256.Scalar, 1000)
			for i := range scalars {
				s := new(k256.Scalar).Random(crand.Reader)
				scalars[i] = s.(*k256.Scalar)
			}
			b.StartTimer()
			for _, sc := range scalars {
				_, _ = sc.Sqrt()
			}
		}
	})
}

type BenchScalar struct {
	value *big.Int

	_ helper_types.Incomparable
}

func (BenchScalar) CurveName() string {
	return k256.Name
}

func (BenchScalar) Curve() (curves.Curve, error) {
	return k256.New(), nil
}

func (s *BenchScalar) Random(reader io.Reader) curves.Scalar {
	var v [32]byte
	_, _ = reader.Read(v[:])
	value := new(big.Int).SetBytes(v[:])
	return &BenchScalar{
		value: value.Mod(value, btcec.S256().N),
	}
}

func (s *BenchScalar) Hash(inputs ...[]byte) curves.Scalar {
	h := sha256.Sum256(bytes.Join(inputs, nil))
	value := new(big.Int).SetBytes(h[:])
	return &BenchScalar{
		value: value.Mod(value, btcec.S256().N),
	}
}

func (s *BenchScalar) Zero() curves.Scalar {
	return &BenchScalar{
		value: big.NewInt(0),
	}
}

func (s *BenchScalar) One() curves.Scalar {
	return &BenchScalar{
		value: big.NewInt(1),
	}
}

func (s *BenchScalar) IsZero() bool {
	return s.value.Cmp(big.NewInt(0)) == 0
}

func (s *BenchScalar) IsOne() bool {
	return s.value.Cmp(big.NewInt(1)) == 0
}

func (s *BenchScalar) IsOdd() bool {
	return s.value.Bit(0) == 1
}

func (s *BenchScalar) IsEven() bool {
	return s.value.Bit(0) == 0
}

func (s *BenchScalar) New(value int) curves.Scalar {
	v := big.NewInt(int64(value))
	return &BenchScalar{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *BenchScalar) Cmp(rhs curves.Scalar) int {
	r := rhs.(*BenchScalar)
	return s.value.Cmp(r.value)
}

func (s *BenchScalar) Square() curves.Scalar {
	v := new(big.Int).Mul(s.value, s.value)
	return &BenchScalar{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *BenchScalar) Double() curves.Scalar {
	v := new(big.Int).Add(s.value, s.value)
	return &BenchScalar{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *BenchScalar) Invert() (curves.Scalar, error) {
	return &BenchScalar{
		value: new(big.Int).ModInverse(s.value, btcec.S256().N),
	}, nil
}

func (s *BenchScalar) Sqrt() (curves.Scalar, error) {
	return &BenchScalar{
		value: new(big.Int).ModSqrt(s.value, btcec.S256().N),
	}, nil
}

func (s *BenchScalar) Cube() curves.Scalar {
	v := new(big.Int).Mul(s.value, s.value)
	v.Mul(v, s.value)
	return &BenchScalar{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *BenchScalar) Add(rhs curves.Scalar) curves.Scalar {
	r := rhs.(*BenchScalar)
	v := new(big.Int).Add(s.value, r.value)
	return &BenchScalar{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *BenchScalar) Sub(rhs curves.Scalar) curves.Scalar {
	r := rhs.(*BenchScalar)
	v := new(big.Int).Sub(s.value, r.value)
	return &BenchScalar{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *BenchScalar) Mul(rhs curves.Scalar) curves.Scalar {
	r := rhs.(*BenchScalar)
	v := new(big.Int).Mul(s.value, r.value)
	return &BenchScalar{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *BenchScalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	yy := y.(*BenchScalar)
	zz := z.(*BenchScalar)
	v := new(big.Int).Mul(s.value, yy.value)
	v.Add(v, zz.value)
	return &BenchScalar{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *BenchScalar) Div(rhs curves.Scalar) curves.Scalar {
	r := rhs.(*BenchScalar)
	v := new(big.Int).ModInverse(r.value, btcec.S256().N)
	v.Mul(v, s.value)
	return &BenchScalar{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *BenchScalar) Exp(k curves.Scalar) curves.Scalar {
	value := new(big.Int).Exp(s.value, k.BigInt(), btcec.S256().N)
	return &BenchScalar{value: value}
}

func (s *BenchScalar) Neg() curves.Scalar {
	v, _ := mod.Neg(s.value, btcec.S256().N)
	return &BenchScalar{
		value: v,
	}
}

func (s *BenchScalar) SetBigInt(v *big.Int) (curves.Scalar, error) {
	return &BenchScalar{
		value: new(big.Int).Set(v),
	}, nil
}

func (s *BenchScalar) BigInt() *big.Int {
	return new(big.Int).Set(s.value)
}

func (s *BenchScalar) Bytes() []byte {
	return bitstring.ReverseBytes(s.value.Bytes())
}

func (s *BenchScalar) SetBytes(bytes []byte) (curves.Scalar, error) {
	value := new(big.Int).SetBytes(bitstring.ReverseBytes(bytes))
	value.Mod(value, btcec.S256().N)
	return &BenchScalar{
		value: value,
	}, nil
}

func (s *BenchScalar) SetBytesWide(bytes []byte) (curves.Scalar, error) {
	value := new(big.Int).SetBytes(bitstring.ReverseBytes(bytes))
	value.Mod(value, btcec.S256().N)
	return &BenchScalar{
		value: value,
	}, nil
}

func (s *BenchScalar) Clone() curves.Scalar {
	return &BenchScalar{
		value: new(big.Int).Set(s.value),
	}
}

type BenchPoint struct {
	x, y *big.Int

	_ helper_types.Incomparable
}

func (p *BenchPoint) Clone() curves.Point {
	return &BenchPoint{
		x: new(big.Int).SetBytes(p.x.Bytes()),
		y: new(big.Int).SetBytes(p.y.Bytes()),
	}
}

func (p *BenchPoint) ClearCofactor() curves.Point {
	return p.Clone()
}

func (BenchPoint) Curve() (curves.Curve, error) {
	return k256.New(), nil
}

func (p *BenchPoint) Random(reader io.Reader) curves.Point {
	var k [32]byte
	curve := btcec.S256()
	_, _ = reader.Read(k[:])
	x, y := curve.ScalarBaseMult(k[:])
	for !curve.IsOnCurve(x, y) {
		_, _ = reader.Read(k[:])
		x, y = curve.ScalarBaseMult(k[:])
	}
	return &BenchPoint{x: x, y: y}
}

func (p *BenchPoint) Hash(bytes ...[]byte) curves.Point {
	return nil
}

func (p *BenchPoint) Identity() curves.Point {
	return &BenchPoint{x: big.NewInt(0), y: big.NewInt(0)}
}

func (p *BenchPoint) Generator() curves.Point {
	return &BenchPoint{
		x: new(big.Int).Set(btcec.S256().Gx),
		y: new(big.Int).Set(btcec.S256().Gy),
	}
}

func (p *BenchPoint) IsIdentity() bool {
	return false
}

func (p *BenchPoint) IsNegative() bool {
	return false
}

func (p *BenchPoint) IsOnCurve() bool {
	return btcec.S256().IsOnCurve(p.x, p.y)
}

func (p *BenchPoint) Double() curves.Point {
	x, y := btcec.S256().Double(p.x, p.y)
	return &BenchPoint{
		x: x, y: y,
	}
}

func (p *BenchPoint) Scalar() curves.Scalar {
	return &BenchScalar{value: big.NewInt(0)}
}

func (p *BenchPoint) Neg() curves.Point {
	y, _ := mod.Neg(p.y, btcec.S256().P)
	return &BenchPoint{
		x: new(big.Int).Set(p.x), y: y,
	}
}

func (p *BenchPoint) Add(rhs curves.Point) curves.Point {
	r := rhs.(*BenchPoint)
	x, y := btcec.S256().Add(p.x, p.y, r.x, r.y)
	return &BenchPoint{
		x: x, y: y,
	}
}

func (p *BenchPoint) Sub(rhs curves.Point) curves.Point {
	t := rhs.Neg().(*BenchPoint)
	return t.Add(p)
}

func (p *BenchPoint) Mul(rhs curves.Scalar) curves.Point {
	k := rhs.Bytes()
	x, y := btcec.S256().ScalarMult(p.x, p.y, k)
	return &BenchPoint{
		x: x, y: y,
	}
}

func (p *BenchPoint) Equal(rhs curves.Point) bool {
	r := rhs.(*BenchPoint)
	return p.x.Cmp(r.x) == 0 && p.y.Cmp(r.y) == 0
}

func (p *BenchPoint) Set(x, y *big.Int) (curves.Point, error) {
	return &BenchPoint{
		x: x, y: y,
	}, nil
}

func (BenchPoint) X() curves.FieldElement {
	return nil
}

func (BenchPoint) Y() curves.FieldElement {
	return nil
}

func (p *BenchPoint) ToAffineCompressed() []byte {
	return nil
}

func (p *BenchPoint) ToAffineUncompressed() []byte {
	return nil
}

func (p *BenchPoint) FromAffineCompressed(bytes []byte) (curves.Point, error) {
	return nil, nil
}

func (p *BenchPoint) FromAffineUncompressed(bytes []byte) (curves.Point, error) {
	return nil, nil
}

func (p *BenchPoint) CurveName() string {
	return btcec.S256().Name
}

//func rhsK256(x *big.Int) *big.Int {
//	// y^2 = x^3 + B
//	x3, _ := mod.Exp(x, big.NewInt(3), btcec.S256().P)
//	x3.Add(x3, btcec.S256().B)
//	return x3.ModSqrt(x3, btcec.S256().P)
//}
