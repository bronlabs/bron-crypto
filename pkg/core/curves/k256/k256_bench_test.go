package k256_test

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var (
	fieldOrder = saferith.ModulusFromNat(new(saferith.Nat).SetBig(btcec.S256().P, btcec.S256().P.BitLen()))
	groupOrder = saferith.ModulusFromNat(new(saferith.Nat).SetBig(btcec.S256().N, btcec.S256().N.BitLen()))
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
			points := make([]*k256.PointK256, 1000)
			for i := range points {
				points[i] = curve.Identity().Random(crand.Reader).(*k256.PointK256)
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
			acc := new(k256.PointK256).Generator()
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
			scalars := make([]*k256.ScalarK256, 1000)
			for i := range scalars {
				s := new(k256.ScalarK256).Random(crand.Reader)
				scalars[i] = s.(*k256.ScalarK256)
			}
			acc := new(k256.PointK256).Generator()
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
			scalars := make([]*k256.ScalarK256, 1000)
			for i := range scalars {
				s := new(k256.ScalarK256).Random(crand.Reader)
				scalars[i] = s.(*k256.ScalarK256)
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
			scalars := make([]*k256.ScalarK256, 1000)
			for i := range scalars {
				s := new(k256.ScalarK256).Random(crand.Reader)
				scalars[i] = s.(*k256.ScalarK256)
			}
			b.StartTimer()
			for _, sc := range scalars {
				_, _ = sc.Sqrt()
			}
		}
	})
}

type BenchScalar struct {
	value *saferith.Nat

	_ helper_types.Incomparable
}

func (*BenchScalar) CurveName() string {
	return k256.Name
}

func (*BenchScalar) Curve() curves.Curve {
	return k256.New()
}

func (s *BenchScalar) Random(reader io.Reader) curves.Scalar {
	var v [32]byte
	_, _ = reader.Read(v[:])
	value := new(saferith.Nat).SetBytes(v[:])
	return &BenchScalar{
		value: value.Mod(value, groupOrder),
	}
}

func (s *BenchScalar) Hash(inputs ...[]byte) curves.Scalar {
	h := sha256.Sum256(bytes.Join(inputs, nil))
	value := new(saferith.Nat).SetBytes(h[:])
	return &BenchScalar{
		value: value.Mod(value, groupOrder),
	}
}

func (s *BenchScalar) Zero() curves.Scalar {
	return &BenchScalar{
		value: new(saferith.Nat).SetUint64(0),
	}
}

func (s *BenchScalar) One() curves.Scalar {
	return &BenchScalar{
		value: new(saferith.Nat).SetUint64(1),
	}
}

func (s *BenchScalar) IsZero() bool {
	return s.value.EqZero() != 0
}

func (s *BenchScalar) IsOne() bool {
	return s.value.Eq(new(saferith.Nat).SetUint64(1)) != 0
}

func (s *BenchScalar) IsOdd() bool {
	return s.value.Byte(0)&0b1 != 0
}

func (s *BenchScalar) IsEven() bool {
	return s.value.Byte(0)&0b1 == 0
}

func (s *BenchScalar) New(value uint64) curves.Scalar {
	v := new(saferith.Nat).SetUint64(value)
	result := &BenchScalar{
		value: v.Mod(v, groupOrder),
	}
	return result
}

func (s *BenchScalar) Cmp(rhs curves.Scalar) int {
	r := rhs.(*BenchScalar)
	b, e, l := s.value.Cmp(r.value)
	if b != 0 {
		return 1
	} else if e != 0 {
		return 0
	} else if l != 0 {
		return -1
	} else {
		panic("should never happen")
	}
}

func (s *BenchScalar) Square() curves.Scalar {
	return &BenchScalar{
		value: new(saferith.Nat).ModMul(s.value, s.value, groupOrder),
	}
}

func (s *BenchScalar) Double() curves.Scalar {
	return &BenchScalar{
		value: new(saferith.Nat).ModAdd(s.value, s.value, groupOrder),
	}
}

func (s *BenchScalar) Invert() (curves.Scalar, error) {
	return &BenchScalar{
		value: new(saferith.Nat).ModInverse(s.value, groupOrder),
	}, nil
}

func (s *BenchScalar) Sqrt() (curves.Scalar, error) {
	return &BenchScalar{
		value: new(saferith.Nat).ModSqrt(s.value, groupOrder),
	}, nil
}

func (s *BenchScalar) Cube() curves.Scalar {
	return &BenchScalar{
		value: new(saferith.Nat).ModMul(new(saferith.Nat).ModMul(s.value, s.value, groupOrder), s.value, groupOrder),
	}
}

func (s *BenchScalar) Add(rhs curves.Scalar) curves.Scalar {
	r := rhs.(*BenchScalar)
	return &BenchScalar{
		value: new(saferith.Nat).ModAdd(r.value, r.value, groupOrder),
	}
}

func (s *BenchScalar) Sub(rhs curves.Scalar) curves.Scalar {
	r := rhs.(*BenchScalar)
	return &BenchScalar{
		value: new(saferith.Nat).ModSub(r.value, r.value, groupOrder),
	}
}

func (s *BenchScalar) Mul(rhs curves.Scalar) curves.Scalar {
	r := rhs.(*BenchScalar)
	return &BenchScalar{
		value: new(saferith.Nat).ModMul(r.value, r.value, groupOrder),
	}
}

func (s *BenchScalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	yy := y.(*BenchScalar)
	zz := z.(*BenchScalar)
	v := new(saferith.Nat).ModMul(s.value, yy.value, groupOrder)
	return &BenchScalar{
		value: new(saferith.Nat).ModAdd(v, zz.value, groupOrder),
	}
}

func (s *BenchScalar) Div(rhs curves.Scalar) curves.Scalar {
	r := rhs.(*BenchScalar)
	v := new(saferith.Nat).ModInverse(r.value, groupOrder)
	return &BenchScalar{
		value: new(saferith.Nat).ModMul(s.value, v, groupOrder),
	}
}

func (s *BenchScalar) Exp(k curves.Scalar) curves.Scalar {
	value := new(saferith.Nat).Exp(s.value, k.Nat(), groupOrder)
	return &BenchScalar{value: value}
}

func (s *BenchScalar) Neg() curves.Scalar {
	return &BenchScalar{
		value: new(saferith.Nat).ModNeg(s.value, groupOrder),
	}
}

func (s *BenchScalar) SetNat(v *saferith.Nat) (curves.Scalar, error) {
	return &BenchScalar{
		value: new(saferith.Nat).Mod(v, groupOrder),
	}, nil
}

func (s *BenchScalar) Nat() *saferith.Nat {
	return new(saferith.Nat).SetNat(s.value)
}

func (s *BenchScalar) Uint64() uint64 {
	return new(saferith.Nat).SetNat(s.value).Big().Uint64()
}

func (s *BenchScalar) Bytes() []byte {
	return bitstring.ReverseBytes(s.value.Bytes())
}

func (s *BenchScalar) SetBytes(bytes []byte) (curves.Scalar, error) {
	value := new(saferith.Nat).SetBytes(bitstring.ReverseBytes(bytes))
	value.Mod(value, groupOrder)
	return &BenchScalar{
		value: value,
	}, nil
}

func (s *BenchScalar) SetBytesWide(bytes []byte) (curves.Scalar, error) {
	value := new(saferith.Nat).SetBytes(bitstring.ReverseBytes(bytes))
	return &BenchScalar{
		value: new(saferith.Nat).Mod(value, groupOrder),
	}, nil
}

func (s *BenchScalar) Clone() curves.Scalar {
	return &BenchScalar{
		value: new(saferith.Nat).SetNat(s.value),
	}
}

type BenchPoint struct {
	x, y *saferith.Nat

	_ helper_types.Incomparable
}

func (p *BenchPoint) Clone() curves.Point {
	return &BenchPoint{
		x: new(saferith.Nat).SetNat(p.x),
		y: new(saferith.Nat).SetNat(p.y),
	}
}

func (p *BenchPoint) ClearCofactor() curves.Point {
	return p.Clone()
}

func (p *BenchPoint) IsSmallOrder() bool {
	return false
}

func (*BenchPoint) Curve() curves.Curve {
	return k256.New()
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
	return &BenchPoint{x: new(saferith.Nat).SetBig(x, btcec.S256().N.BitLen()), y: new(saferith.Nat).SetBig(y, btcec.S256().N.BitLen())}
}

func (p *BenchPoint) Hash(bytes ...[]byte) curves.Point {
	return nil
}

func (p *BenchPoint) Identity() curves.Point {
	return &BenchPoint{x: new(saferith.Nat).SetUint64(0), y: new(saferith.Nat).SetUint64(0)}
}

func (p *BenchPoint) Generator() curves.Point {
	return &BenchPoint{
		x: new(saferith.Nat).SetBig(btcec.S256().Gx, fieldOrder.BitLen()),
		y: new(saferith.Nat).SetBig(btcec.S256().Gy, fieldOrder.BitLen()),
	}
}

func (p *BenchPoint) IsIdentity() bool {
	return false
}

func (p *BenchPoint) IsNegative() bool {
	return false
}

func (p *BenchPoint) IsOnCurve() bool {
	return btcec.S256().IsOnCurve(p.x.Big(), p.y.Big())
}

func (p *BenchPoint) Double() curves.Point {
	x, y := btcec.S256().Double(p.x.Big(), p.y.Big())
	return &BenchPoint{
		x: new(saferith.Nat).SetBig(x, fieldOrder.BitLen()), y: new(saferith.Nat).SetBig(y, fieldOrder.BitLen()),
	}
}

func (p *BenchPoint) Scalar() curves.Scalar {
	return &BenchScalar{value: new(saferith.Nat).Mod(new(saferith.Nat).SetUint64(0), fieldOrder)}
}

func (p *BenchPoint) Neg() curves.Point {
	return &BenchPoint{
		x: new(saferith.Nat).SetNat(p.x),
		y: new(saferith.Nat).ModNeg(p.y, fieldOrder),
	}
}

func (p *BenchPoint) Add(rhs curves.Point) curves.Point {
	r := rhs.(*BenchPoint)
	x, y := btcec.S256().Add(p.x.Big(), p.y.Big(), r.x.Big(), r.y.Big())
	return &BenchPoint{
		x: new(saferith.Nat).SetBig(x, fieldOrder.BitLen()),
		y: new(saferith.Nat).SetBig(y, fieldOrder.BitLen()),
	}
}

func (p *BenchPoint) Sub(rhs curves.Point) curves.Point {
	t := rhs.Neg().(*BenchPoint)
	return t.Add(p)
}

func (p *BenchPoint) Mul(rhs curves.Scalar) curves.Point {
	k := rhs.Bytes()
	x, y := btcec.S256().ScalarMult(p.x.Big(), p.y.Big(), k)
	return &BenchPoint{
		x: new(saferith.Nat).SetBig(x, fieldOrder.BitLen()),
		y: new(saferith.Nat).SetBig(y, fieldOrder.BitLen()),
	}
}

func (p *BenchPoint) Equal(rhs curves.Point) bool {
	r := rhs.(*BenchPoint)
	return p.x.Eq(r.x) != 0 && p.y.Eq(r.y) != 0
}

func (p *BenchPoint) Set(x, y *saferith.Nat) (curves.Point, error) {
	return &BenchPoint{
		x: x, y: y,
	}, nil
}

func (*BenchPoint) X() curves.FieldElement {
	return nil
}

func (*BenchPoint) Y() curves.FieldElement {
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
