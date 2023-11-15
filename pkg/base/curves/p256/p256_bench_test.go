package p256

import (
	"bytes"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var (
	fieldOrder = saferith.ModulusFromNat(new(saferith.Nat).SetBig(elliptic.P256().Params().P, elliptic.P256().Params().P.BitLen()))
	groupOrder = saferith.ModulusFromNat(new(saferith.Nat).SetBig(elliptic.P256().Params().N, elliptic.P256().Params().N.BitLen()))
)

func BenchmarkP256(b *testing.B) {
	// 1000 points

	b.Run("1000 point hash - p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			points := make([][]byte, 1000)
			for i := range points {
				t := make([]byte, 32)
				_, _ = crand.Read(t)
				points[i] = t
			}
			acc := new(BenchPoint).Identity()
			b.StartTimer()
			for _, pt := range points {
				acc, _ = acc.Hash(pt)
			}
		}
	})

	b.Run("1000 point hash - ct p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			points := make([][]byte, 1000)
			for i := range points {
				t := make([]byte, 32)
				_, _ = crand.Read(t)
				points[i] = t
			}
			acc := new(Point).Identity()
			b.StartTimer()
			for _, pt := range points {
				acc, _ = acc.Hash(pt)
			}
		}
	})

	b.Run("1000 point add - p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			points := make([]*BenchPoint, 1000)
			for i := range points {
				p, err := points[i].Random(crand.Reader)
				require.NoError(b, err)
				points[i] = p.(*BenchPoint)
			}
			acc := new(BenchPoint).Identity()
			b.StartTimer()
			for _, pt := range points {
				acc = acc.Add(pt)
			}
		}
	})
	b.Run("1000 point add - ct p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			curve := New()
			points := make([]*Point, 1000)
			for i := range points {
				p, err := curve.Identity().Random(crand.Reader)
				require.NoError(b, err)
				points[i] = p.(*Point)
			}
			acc := curve.Identity()
			b.StartTimer()
			for _, pt := range points {
				acc = acc.Add(pt)
			}
		}
	})
	b.Run("1000 point double - p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			acc := new(BenchPoint).Generator()
			b.StartTimer()
			for i := 0; i < 1000; i++ {
				acc = acc.Double()
			}
		}
	})
	b.Run("1000 point double - ct p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			acc := new(Point).Generator()
			b.StartTimer()
			for i := 0; i < 1000; i++ {
				acc = acc.Double()
			}
		}
	})
	b.Run("1000 point multiply - p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*BenchScalar, 1000)
			for i := range scalars {
				s, err := new(BenchScalar).Random(crand.Reader)
				require.NoError(b, err)
				scalars[i] = s.(*BenchScalar)
			}
			acc := new(BenchPoint).Generator().Mul(new(BenchScalar).New(2))
			b.StartTimer()
			for _, sc := range scalars {
				acc = acc.Mul(sc)
			}
		}
	})
	b.Run("1000 point multiply - ct p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*Scalar, 1000)
			for i := range scalars {
				s, err := new(Scalar).Random(crand.Reader)
				require.NoError(b, err)
				scalars[i] = s.(*Scalar)
			}
			acc := new(Point).Generator()
			b.StartTimer()
			for _, sc := range scalars {
				acc = acc.Mul(sc)
			}
		}
	})
	b.Run("1000 scalar invert - p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*BenchScalar, 1000)
			for i := range scalars {
				s, err := new(BenchScalar).Random(crand.Reader)
				require.NoError(b, err)
				scalars[i] = s.(*BenchScalar)
			}
			b.StartTimer()
			for _, sc := range scalars {
				_, _ = sc.Invert()
			}
		}
	})
	b.Run("1000 scalar invert - ct p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*Scalar, 1000)
			for i := range scalars {
				s, err := new(Scalar).Random(crand.Reader)
				require.NoError(b, err)
				scalars[i] = s.(*Scalar)
			}
			b.StartTimer()
			for _, sc := range scalars {
				_, _ = sc.Invert()
			}
		}
	})
	b.Run("1000 scalar sqrt - p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*BenchScalar, 1000)
			for i := range scalars {
				s, err := new(BenchScalar).Random(crand.Reader)
				require.NoError(b, err)
				scalars[i] = s.(*BenchScalar)
			}
			b.StartTimer()
			for _, sc := range scalars {
				_, _ = sc.Sqrt()
			}
		}
	})
	b.Run("1000 scalar sqrt - ct p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*Scalar, 1000)
			for i := range scalars {
				s, err := new(Scalar).Random(crand.Reader)
				require.NoError(b, err)
				scalars[i] = s.(*Scalar)
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

	_ types.Incomparable
}

type BenchPoint struct {
	x, y *saferith.Nat

	_ types.Incomparable
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

func (*BenchScalar) CurveName() string {
	return Name
}

func (*BenchPoint) Curve() curves.Curve {
	return New()
}

func (*BenchScalar) Curve() curves.Curve {
	return New()
}

func (s *BenchScalar) Random(reader io.Reader) (curves.Scalar, error) {
	if reader == nil {
		return nil, errs.NewIsNil("reader is nil")
	}
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return s.Hash(seed[:])
}

func (s *BenchScalar) Hash(inputs ...[]byte) (curves.Scalar, error) {
	dst := append([]byte("P256_XMD:SHA-256_SSWU_RO_"), []byte(base.HASH2CURVE_APP_TAG)...)
	xmd, err := testutils.ExpandMsgXmd(sha256.New(), bytes.Join(inputs, nil), dst, 48)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not hash")
	}
	v := new(saferith.Nat).SetBytes(xmd)
	return &BenchScalar{
		value: new(saferith.Nat).Mod(v, groupOrder),
	}, nil
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
	r, ok := rhs.(*BenchScalar)
	if ok {
		b, e, l := s.value.Cmp(r.value)
		if l != 0 {
			return -1
		} else if e != 0 {
			return 0
		} else if b != 0 {
			return 1
		}
	}

	return -2
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
		value: new(saferith.Nat).Exp(s.value, new(saferith.Nat).SetUint64(3), groupOrder),
	}
}

func (s *BenchScalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*BenchScalar)
	if ok {
		return &BenchScalar{
			value: new(saferith.Nat).ModAdd(s.value, r.value, groupOrder),
		}
	} else {
		return nil
	}
}

func (s *BenchScalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*BenchScalar)
	if ok {
		return &BenchScalar{
			value: new(saferith.Nat).ModSub(s.value, r.value, groupOrder),
		}
	} else {
		return nil
	}
}

func (s *BenchScalar) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*BenchScalar)
	if ok {
		return &BenchScalar{
			value: new(saferith.Nat).ModMul(s.value, r.value, groupOrder),
		}
	} else {
		return nil
	}
}

func (s *BenchScalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *BenchScalar) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*BenchScalar)
	if ok {
		v := new(saferith.Nat).ModInverse(r.value, groupOrder)
		return &BenchScalar{
			value: new(saferith.Nat).ModMul(s.value, v, groupOrder),
		}
	} else {
		return nil
	}
}

func (s *BenchScalar) Exp(k curves.Scalar) curves.Scalar {
	value := new(saferith.Nat).ModMul(s.value, k.Nat(), groupOrder)
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
	var out [32]byte
	return s.value.FillBytes(out[:])
}

func (s *BenchScalar) SetBytes(bytes []byte) (curves.Scalar, error) {
	value := new(saferith.Nat).SetBytes(bytes)
	t := new(saferith.Nat).Mod(value, groupOrder)
	if t.Eq(value) == 0 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	return &BenchScalar{
		value: t,
	}, nil
}

func (s *BenchScalar) SetBytesWide(bytes []byte) (curves.Scalar, error) {
	if len(bytes) < 32 || len(bytes) > 128 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	value := new(saferith.Nat).SetBytes(bytes)
	value.Mod(value, groupOrder)
	return &BenchScalar{
		value: value,
	}, nil
}

func (s *BenchScalar) Clone() curves.Scalar {
	return &BenchScalar{
		value: new(saferith.Nat).SetNat(s.value),
	}
}

func (s *BenchScalar) MarshalBinary() ([]byte, error) {
	return serialisation.ScalarMarshalBinary(s)
}

func (s *BenchScalar) UnmarshalBinary(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalBinary(New().Name(), s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*BenchScalar)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *BenchScalar) MarshalText() ([]byte, error) {
	return serialisation.ScalarMarshalText(s)
}

func (s *BenchScalar) UnmarshalText(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalText(New().Name(), s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*BenchScalar)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *BenchScalar) MarshalJSON() ([]byte, error) {
	return serialisation.ScalarMarshalJson(New().Name(), s)
}

func (s *BenchScalar) UnmarshalJSON(input []byte) error {
	sc, err := serialisation.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	S, ok := sc.(*BenchScalar)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	s.value = S.value
	return nil
}

func (p *BenchPoint) Random(reader io.Reader) (curves.Point, error) {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *BenchPoint) Hash(inputs ...[]byte) (curves.Point, error) {
	curve := elliptic.P256().Params()

	domain := []byte("P256_XMD:SHA-256_SSWU_RO_")
	uniformBytes, _ := testutils.ExpandMsgXmd(sha256.New(), bytes.Join(inputs, nil), domain, 96)

	u0 := new(big.Int).SetBytes(uniformBytes[:48])
	u1 := new(big.Int).SetBytes(uniformBytes[48:])

	u0.Mod(u0, curve.P)
	u1.Mod(u1, curve.P)

	ssParams := p256SswuParams()
	q0x, q0y := testutils.Osswu3mod4(u0, ssParams)
	q1x, q1y := testutils.Osswu3mod4(u1, ssParams)

	// Since P-256 does not require the isogeny map just add the points
	x, y := curve.Add(q0x, q0y, q1x, q1y)

	return &BenchPoint{
		x: new(saferith.Nat).SetBig(x, fieldOrder.BitLen()),
		y: new(saferith.Nat).SetBig(y, fieldOrder.BitLen()),
	}, nil
}

func (p *BenchPoint) Identity() curves.Point {
	return &BenchPoint{
		x: new(saferith.Nat).SetUint64(0),
		y: new(saferith.Nat).SetUint64(0),
	}
}

func (p *BenchPoint) Generator() curves.Point {
	curve := elliptic.P256().Params()
	return &BenchPoint{
		x: new(saferith.Nat).SetBig(curve.Gx, fieldOrder.BitLen()),
		y: new(saferith.Nat).SetBig(curve.Gy, fieldOrder.BitLen()),
	}
}

func (p *BenchPoint) IsIdentity() bool {
	x := p.x.EqZero()
	y := p.y.EqZero()
	return (x & y) != 0
}

func (p *BenchPoint) IsNegative() bool {
	return p.y.Byte(0)&0b1 != 0
}

func (p *BenchPoint) IsOnCurve() bool {
	return elliptic.P256().IsOnCurve(p.x.Big(), p.y.Big())
}

func (p *BenchPoint) Double() curves.Point {
	curve := elliptic.P256()
	x, y := curve.Double(p.x.Big(), p.y.Big())
	return &BenchPoint{x: new(saferith.Nat).SetBig(x, fieldOrder.BitLen()), y: new(saferith.Nat).SetBig(y, fieldOrder.BitLen())}
}

func (p *BenchPoint) Scalar() curves.Scalar {
	return new(BenchScalar).Zero()
}

func (p *BenchPoint) Neg() curves.Point {
	y := new(saferith.Nat).ModNeg(p.y, fieldOrder)
	return &BenchPoint{x: p.x, y: y}
}

func (p *BenchPoint) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*BenchPoint)
	if ok {
		x, y := elliptic.P256().Add(p.x.Big(), p.y.Big(), r.x.Big(), r.y.Big())
		return &BenchPoint{x: new(saferith.Nat).SetBig(x, fieldOrder.BitLen()), y: new(saferith.Nat).SetBig(y, fieldOrder.BitLen())}
	} else {
		return nil
	}
}

func (p *BenchPoint) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.Neg().(*BenchPoint)
	if ok {
		x, y := elliptic.P256().Add(p.x.Big(), p.y.Big(), r.x.Big(), r.y.Big())
		return &BenchPoint{x: new(saferith.Nat).SetBig(x, fieldOrder.BitLen()), y: new(saferith.Nat).SetBig(y, fieldOrder.BitLen())}
	} else {
		return nil
	}
}

func (p *BenchPoint) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*BenchScalar)
	if ok {
		x, y := elliptic.P256().ScalarMult(p.x.Big(), p.y.Big(), r.value.Bytes())
		return &BenchPoint{x: new(saferith.Nat).SetBig(x, fieldOrder.BitLen()), y: new(saferith.Nat).SetBig(y, fieldOrder.BitLen())}
	} else {
		return nil
	}
}

func (p *BenchPoint) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*BenchPoint)
	if ok {
		x := p.x.Eq(r.x)
		y := p.y.Eq(r.y)
		return (x & y) != 0
	} else {
		return false
	}
}

func (p *BenchPoint) Set(x, y *saferith.Nat) (curves.Point, error) {
	// check is identity or on curve
	xx := subtle.ConstantTimeCompare(x.Bytes(), []byte{})
	yy := subtle.ConstantTimeCompare(y.Bytes(), []byte{})
	// Checks are constant time
	onCurve := elliptic.P256().IsOnCurve(x.Big(), y.Big())
	if !onCurve && (xx&yy) == 0 {
		return nil, fmt.Errorf("invalid coordinates")
	}
	return &BenchPoint{x: x, y: y}, nil
}

func (p *BenchPoint) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)
	x[0] |= p.y.Byte(0) & 0b1
	p.x.FillBytes(x[1:])
	return x[:]
}

func (p *BenchPoint) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	p.x.FillBytes(out[1:33])
	p.y.FillBytes(out[33:])
	return out[:]
}

func (p *BenchPoint) FromAffineCompressed(bytes []byte) (curves.Point, error) {
	if len(bytes) != 33 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	sign := int(bytes[0])
	if sign != 2 && sign != 3 {
		return nil, fmt.Errorf("invalid sign byte")
	}
	sign &= 0b1

	x := new(saferith.Nat).SetBytes(bytes[1:])
	rhs := rhsP256(x.Big(), elliptic.P256().Params())
	// test that rhs is quadratic residue
	// if not, then this curves.Point is at infinity
	y := new(saferith.Nat).ModSqrt(new(saferith.Nat).SetBig(rhs, fieldOrder.BitLen()), fieldOrder)
	if y != nil {
		// fix the sign
		if y.Byte(0)&0b1 != byte(sign) {
			y.ModNeg(y, fieldOrder)
		}
	} else {
		x = new(saferith.Nat)
		y = new(saferith.Nat)
	}
	return &BenchPoint{
		x: x, y: y,
	}, nil
}

func (p *BenchPoint) FromAffineUncompressed(bytes []byte) (curves.Point, error) {
	if len(bytes) != 65 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	if bytes[0] != 4 {
		return nil, fmt.Errorf("invalid sign byte")
	}
	x := new(saferith.Nat).SetBytes(bytes[1:33])
	y := new(saferith.Nat).SetBytes(bytes[33:])
	return &BenchPoint{x: x, y: y}, nil
}

func (p *BenchPoint) CurveName() string {
	return elliptic.P256().Params().Name
}

func (*BenchPoint) X() curves.FieldElement {
	return nil
}

func (*BenchPoint) Y() curves.FieldElement {
	return nil
}

func (p *BenchPoint) Params() *elliptic.CurveParams {
	return elliptic.P256().Params()
}

func (p *BenchPoint) MarshalBinary() ([]byte, error) {
	return serialisation.PointMarshalBinary(p)
}

func (p *BenchPoint) UnmarshalBinary(input []byte) error {
	pt, err := serialisation.PointUnmarshalBinary(New(), input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ppt, ok := pt.(*BenchPoint)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.x = ppt.x
	p.y = ppt.y
	return nil
}

func (p *BenchPoint) MarshalText() ([]byte, error) {
	return serialisation.PointMarshalText(p)
}

func (p *BenchPoint) UnmarshalText(input []byte) error {
	pt, err := serialisation.PointUnmarshalText(New(), input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ppt, ok := pt.(*BenchPoint)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.x = ppt.x
	p.y = ppt.y
	return nil
}

func (p *BenchPoint) MarshalJSON() ([]byte, error) {
	return serialisation.PointMarshalJson(p)
}

func (p *BenchPoint) UnmarshalJSON(input []byte) error {
	pt, err := serialisation.NewPointFromJSON(New(), input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	P, ok := pt.(*BenchPoint)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	p.x = P.x
	p.y = P.y
	return nil
}

// From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-8.2
func p256SswuParams() *testutils.SswuParams {
	params := elliptic.P256().Params()

	// c1 = (q - 3) / 4
	c1 := new(big.Int).Set(params.P)
	c1.Sub(c1, big.NewInt(3))
	c1.Rsh(c1, 2)

	a := big.NewInt(-3)
	a.Mod(a, params.P)
	b := new(big.Int).Set(params.B)
	z := big.NewInt(-10)
	z.Mod(z, params.P)
	// sqrt(-Z^3)
	zTmp := new(big.Int).Exp(z, big.NewInt(3), nil)
	zTmp = zTmp.Neg(zTmp)
	zTmp.Mod(zTmp, params.P)
	c2 := new(big.Int).ModSqrt(zTmp, params.P)

	return &testutils.SswuParams{
		Params: params,
		C1:     c1,
		C2:     c2,
		A:      a,
		B:      b,
		Z:      z,
	}
}

// rhs of the curve equation
func rhsP256(x *big.Int, params *elliptic.CurveParams) *big.Int {
	f := testutils.NewField(params.P)
	r := f.NewElement(x)
	r2 := r.Mul(r)

	// x^3-3x+B
	a := r.Mul(f.NewElement(big.NewInt(3)))
	r = r2.Mul(r)
	return r.Add(a.Neg()).Add(f.NewElement(params.B)).Value
}
