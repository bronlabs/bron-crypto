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

	"github.com/copperexchange/knox-primitives/pkg/core"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
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
				acc = acc.Hash(pt)
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
				acc = acc.Hash(pt)
			}
		}
	})

	b.Run("1000 point add - p256", func(b *testing.B) {
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
	b.Run("1000 point add - ct p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			curve := New()
			points := make([]*Point, 1000)
			for i := range points {
				points[i] = curve.Identity().Random(crand.Reader).(*Point)
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
	b.Run("1000 point multiply - ct p256", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			scalars := make([]*Scalar, 1000)
			for i := range scalars {
				s := new(Scalar).Random(crand.Reader)
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
				s := new(BenchScalar).Random(crand.Reader)
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
				s := new(Scalar).Random(crand.Reader)
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
				s := new(BenchScalar).Random(crand.Reader)
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
				s := new(Scalar).Random(crand.Reader)
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
	value *big.Int

	_ helper_types.Incomparable
}

type BenchPoint struct {
	x, y *big.Int

	_ helper_types.Incomparable
}

func (BenchScalar) CurveName() string {
	return Name
}

func (BenchPoint) Curve() (curves.Curve, error) {
	return New(), nil
}

func (BenchScalar) Curve() (curves.Curve, error) {
	return New(), nil
}

func (s *BenchScalar) Random(reader io.Reader) curves.Scalar {
	if reader == nil {
		return nil
	}
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return s.Hash(seed[:])
}

func (s *BenchScalar) Hash(inputs ...[]byte) curves.Scalar {
	xmd, err := test_utils.ExpandMsgXmd(sha256.New(), bytes.Join(inputs, nil), []byte("P256_XMD:SHA-256_SSWU_RO_"), 48)
	if err != nil {
		return nil
	}
	v := new(big.Int).SetBytes(xmd)
	return &BenchScalar{
		value: v.Mod(v, elliptic.P256().Params().N),
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
	return subtle.ConstantTimeCompare(s.value.Bytes(), []byte{}) == 1
}

func (s *BenchScalar) IsOne() bool {
	return subtle.ConstantTimeCompare(s.value.Bytes(), []byte{1}) == 1
}

func (s *BenchScalar) IsOdd() bool {
	return s.value.Bit(0) == 1
}

func (s *BenchScalar) IsEven() bool {
	return s.value.Bit(0) == 0
}

func (s *BenchScalar) New(value int) curves.Scalar {
	v := big.NewInt(int64(value))
	if value < 0 {
		v.Mod(v, elliptic.P256().Params().N)
	}
	return &BenchScalar{
		value: v,
	}
}

func (s *BenchScalar) Cmp(rhs curves.Scalar) int {
	r, ok := rhs.(*BenchScalar)
	if ok {
		return s.value.Cmp(r.value)
	} else {
		return -2
	}
}

func (s *BenchScalar) Square() curves.Scalar {
	return &BenchScalar{
		value: new(big.Int).Exp(s.value, big.NewInt(2), elliptic.P256().Params().N),
	}
}

func (s *BenchScalar) Double() curves.Scalar {
	v := new(big.Int).Add(s.value, s.value)
	return &BenchScalar{
		value: v.Mod(v, elliptic.P256().Params().N),
	}
}

func (s *BenchScalar) Invert() (curves.Scalar, error) {
	return &BenchScalar{
		value: new(big.Int).ModInverse(s.value, elliptic.P256().Params().N),
	}, nil
}

func (s *BenchScalar) Sqrt() (curves.Scalar, error) {
	return &BenchScalar{
		value: new(big.Int).ModSqrt(s.value, elliptic.P256().Params().N),
	}, nil
}

func (s *BenchScalar) Cube() curves.Scalar {
	return &BenchScalar{
		value: new(big.Int).Exp(s.value, big.NewInt(3), elliptic.P256().Params().N),
	}
}

func (s *BenchScalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*BenchScalar)
	if ok {
		v := new(big.Int).Add(s.value, r.value)
		return &BenchScalar{
			value: v.Mod(v, elliptic.P256().Params().N),
		}
	} else {
		return nil
	}
}

func (s *BenchScalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*BenchScalar)
	if ok {
		v := new(big.Int).Sub(s.value, r.value)
		return &BenchScalar{
			value: v.Mod(v, elliptic.P256().Params().N),
		}
	} else {
		return nil
	}
}

func (s *BenchScalar) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*BenchScalar)
	if ok {
		v := new(big.Int).Mul(s.value, r.value)
		return &BenchScalar{
			value: v.Mod(v, elliptic.P256().Params().N),
		}
	} else {
		return nil
	}
}

func (s *BenchScalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *BenchScalar) Div(rhs curves.Scalar) curves.Scalar {
	n := elliptic.P256().Params().N
	r, ok := rhs.(*BenchScalar)
	if ok {
		v := new(big.Int).ModInverse(r.value, n)
		v.Mul(v, s.value)
		return &BenchScalar{
			value: v.Mod(v, n),
		}
	} else {
		return nil
	}
}

func (s *BenchScalar) Exp(k curves.Scalar) curves.Scalar {
	value := new(big.Int).Exp(s.value, k.BigInt(), elliptic.P256().Params().N)
	return &BenchScalar{value: value}
}

func (s *BenchScalar) Neg() curves.Scalar {
	z := new(big.Int).Neg(s.value)
	return &BenchScalar{
		value: z.Mod(z, elliptic.P256().Params().N),
	}
}

func (s *BenchScalar) SetBigInt(v *big.Int) (curves.Scalar, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid value")
	}
	t := new(big.Int).Mod(v, elliptic.P256().Params().N)
	if t.Cmp(v) != 0 {
		return nil, fmt.Errorf("invalid value")
	}
	return &BenchScalar{
		value: t,
	}, nil
}

func (s *BenchScalar) BigInt() *big.Int {
	return new(big.Int).Set(s.value)
}

func (s *BenchScalar) Bytes() []byte {
	var out [32]byte
	return s.value.FillBytes(out[:])
}

func (s *BenchScalar) SetBytes(bytes []byte) (curves.Scalar, error) {
	value := new(big.Int).SetBytes(bytes)
	t := new(big.Int).Mod(value, elliptic.P256().Params().N)
	if t.Cmp(value) != 0 {
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
	value := new(big.Int).SetBytes(bytes)
	value.Mod(value, elliptic.P256().Params().N)
	return &BenchScalar{
		value: value,
	}, nil
}

func (s *BenchScalar) Clone() curves.Scalar {
	return &BenchScalar{
		value: new(big.Int).Set(s.value),
	}
}

func (s *BenchScalar) MarshalBinary() ([]byte, error) {
	return internal.ScalarMarshalBinary(s)
}

func (s *BenchScalar) UnmarshalBinary(input []byte) error {
	sc, err := internal.ScalarUnmarshalBinary(New().Name(), s.SetBytes, input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*BenchScalar)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *BenchScalar) MarshalText() ([]byte, error) {
	return internal.ScalarMarshalText(s)
}

func (s *BenchScalar) UnmarshalText(input []byte) error {
	sc, err := internal.ScalarUnmarshalText(New().Name(), s.SetBytes, input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*BenchScalar)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *BenchScalar) MarshalJSON() ([]byte, error) {
	return internal.ScalarMarshalJson(New().Name(), s)
}

func (s *BenchScalar) UnmarshalJSON(input []byte) error {
	sc, err := internal.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return err
	}
	S, ok := sc.(*BenchScalar)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	s.value = S.value
	return nil
}

func (p *BenchPoint) Random(reader io.Reader) curves.Point {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *BenchPoint) Hash(inputs ...[]byte) curves.Point {
	curve := elliptic.P256().Params()

	domain := []byte("P256_XMD:SHA-256_SSWU_RO_")
	uniformBytes, _ := test_utils.ExpandMsgXmd(sha256.New(), bytes.Join(inputs, nil), domain, 96)

	u0 := new(big.Int).SetBytes(uniformBytes[:48])
	u1 := new(big.Int).SetBytes(uniformBytes[48:])

	u0.Mod(u0, curve.P)
	u1.Mod(u1, curve.P)

	ssParams := p256SswuParams()
	q0x, q0y := test_utils.Osswu3mod4(u0, ssParams)
	q1x, q1y := test_utils.Osswu3mod4(u1, ssParams)

	// Since P-256 does not require the isogeny map just add the points
	x, y := curve.Add(q0x, q0y, q1x, q1y)

	return &BenchPoint{
		x: x, y: y,
	}
}

func (p *BenchPoint) Identity() curves.Point {
	return &BenchPoint{
		x: big.NewInt(0), y: big.NewInt(0),
	}
}

func (p *BenchPoint) Generator() curves.Point {
	curve := elliptic.P256().Params()
	return &BenchPoint{
		x: new(big.Int).Set(curve.Gx),
		y: new(big.Int).Set(curve.Gy),
	}
}

func (p *BenchPoint) IsIdentity() bool {
	x := core.ConstantTimeEqByte(p.x, core.Zero)
	y := core.ConstantTimeEqByte(p.y, core.Zero)
	return (x & y) == 1
}

func (p *BenchPoint) IsNegative() bool {
	return p.y.Bit(0) == 1
}

func (p *BenchPoint) IsOnCurve() bool {
	return elliptic.P256().IsOnCurve(p.x, p.y)
}

func (p *BenchPoint) Double() curves.Point {
	curve := elliptic.P256()
	x, y := curve.Double(p.x, p.y)
	return &BenchPoint{x: x, y: y}
}

func (p *BenchPoint) Scalar() curves.Scalar {
	return new(BenchScalar).Zero()
}

func (p *BenchPoint) Neg() curves.Point {
	y := new(big.Int).Sub(elliptic.P256().Params().P, p.y)
	y.Mod(y, elliptic.P256().Params().P)
	return &BenchPoint{x: p.x, y: y}
}

func (p *BenchPoint) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*BenchPoint)
	if ok {
		x, y := elliptic.P256().Add(p.x, p.y, r.x, r.y)
		return &BenchPoint{x: x, y: y}
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
		x, y := elliptic.P256().Add(p.x, p.y, r.x, r.y)
		return &BenchPoint{x: x, y: y}
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
		x, y := elliptic.P256().ScalarMult(p.x, p.y, r.value.Bytes())
		return &BenchPoint{x: x, y: y}
	} else {
		return nil
	}
}

func (p *BenchPoint) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*BenchPoint)
	if ok {
		x := core.ConstantTimeEqByte(p.x, r.x)
		y := core.ConstantTimeEqByte(p.y, r.y)
		return (x & y) == 1
	} else {
		return false
	}
}

func (p *BenchPoint) Set(x, y *big.Int) (curves.Point, error) {
	// check is identity or on curve
	xx := subtle.ConstantTimeCompare(x.Bytes(), []byte{})
	yy := subtle.ConstantTimeCompare(y.Bytes(), []byte{})
	// Checks are constant time
	onCurve := elliptic.P256().IsOnCurve(x, y)
	if !onCurve && (xx&yy) != 1 {
		return nil, fmt.Errorf("invalid coordinates")
	}
	x = new(big.Int).Set(x)
	y = new(big.Int).Set(y)
	return &BenchPoint{x: x, y: y}, nil
}

func (p *BenchPoint) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)
	x[0] |= byte(p.y.Bit(0))
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
	sign &= 0x1

	x := new(big.Int).SetBytes(bytes[1:])
	rhs := rhsP256(x, elliptic.P256().Params())
	// test that rhs is quadratic residue
	// if not, then this curves.Point is at infinity
	y := new(big.Int).ModSqrt(rhs, elliptic.P256().Params().P)
	if y != nil {
		// fix the sign
		if int(y.Bit(0)) != sign {
			y.Neg(y)
			y.Mod(y, elliptic.P256().Params().P)
		}
	} else {
		x = new(big.Int)
		y = new(big.Int)
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
	x := new(big.Int).SetBytes(bytes[1:33])
	y := new(big.Int).SetBytes(bytes[33:])
	return &BenchPoint{x: x, y: y}, nil
}

func (p *BenchPoint) CurveName() string {
	return elliptic.P256().Params().Name
}

func (BenchPoint) X() curves.FieldElement {
	return nil
}

func (BenchPoint) Y() curves.FieldElement {
	return nil
}

func (p *BenchPoint) Params() *elliptic.CurveParams {
	return elliptic.P256().Params()
}

func (p *BenchPoint) MarshalBinary() ([]byte, error) {
	return internal.PointMarshalBinary(p)
}

func (p *BenchPoint) UnmarshalBinary(input []byte) error {
	pt, err := internal.PointUnmarshalBinary(New(), input)
	if err != nil {
		return err
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
	return internal.PointMarshalText(p)
}

func (p *BenchPoint) UnmarshalText(input []byte) error {
	pt, err := internal.PointUnmarshalText(New(), input)
	if err != nil {
		return err
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
	return internal.PointMarshalJson(p)
}

func (p *BenchPoint) UnmarshalJSON(input []byte) error {
	pt, err := internal.NewPointFromJSON(New(), input)
	if err != nil {
		return err
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
func p256SswuParams() *test_utils.SswuParams {
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

	return &test_utils.SswuParams{
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
	f := test_utils.NewField(params.P)
	r := f.NewElement(x)
	r2 := r.Mul(r)

	// x^3-3x+B
	a := r.Mul(f.NewElement(big.NewInt(3)))
	r = r2.Mul(r)
	return r.Add(a.Neg()).Add(f.NewElement(params.B)).Value
}
