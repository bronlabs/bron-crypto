package fq_test

import (
	crand "crypto/rand"
	"io"
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pallas/impl/fq"
)

func TestFqSetOne(t *testing.T) {
	t.Parallel()

	fqOne := new(fq.Fq).SetOne()
	require.NotNil(t, fqOne)

	var fqRandom *fq.Fq
	for fqRandom == nil || fqRandom.IsZero() {
		var randomBytes [64]byte
		_, err := io.ReadFull(crand.Reader, randomBytes[:])
		require.NoError(t, err)
		fqRandom = new(fq.Fq).SetBytesWide(&randomBytes)
	}
	require.NotNil(t, fqRandom)
	require.False(t, fqRandom.IsZero())

	fqOneTimesRandom := new(fq.Fq).Mul(fqOne, fqRandom)
	require.NotNil(t, fqOneTimesRandom)
	require.True(t, fqRandom.Equal(fqOneTimesRandom))
}

func TestFqSetUint64(t *testing.T) {
	t.Parallel()
	act := new(fq.Fq).SetUint64(1 << 60)
	require.NotNil(t, act)
	// Remember it will be in montgomery form
	require.Equal(t, int64(0x4c46eb2100000001), int64(act[0]))
}

func TestFqAdd(t *testing.T) {
	t.Parallel()
	lhs := new(fq.Fq).SetOne()
	rhs := new(fq.Fq).SetOne()
	exp := new(fq.Fq).SetUint64(2)
	res := new(fq.Fq).Add(lhs, rhs)
	require.NotNil(t, res)
	require.True(t, res.Equal(exp))

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint64() >> 2
		r := rand.Uint64() >> 2
		e := l + r
		lhs.SetUint64(l)
		rhs.SetUint64(r)
		exp.SetUint64(e)

		a := new(fq.Fq).Add(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqSub(t *testing.T) {
	t.Parallel()
	lhs := new(fq.Fq).SetOne()
	rhs := new(fq.Fq).SetOne()
	exp := new(fq.Fq).SetZero()
	res := new(fq.Fq).Sub(lhs, rhs)
	require.NotNil(t, res)
	require.True(t, res.Equal(exp))

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint64() >> 2
		r := rand.Uint64() >> 2
		if l < r {
			l, r = r, l
		}
		e := l - r
		lhs.SetUint64(l)
		rhs.SetUint64(r)
		exp.SetUint64(e)

		a := new(fq.Fq).Sub(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqMul(t *testing.T) {
	t.Parallel()
	lhs := new(fq.Fq).SetOne()
	rhs := new(fq.Fq).SetOne()
	exp := new(fq.Fq).SetOne()
	res := new(fq.Fq).Mul(lhs, rhs)
	require.NotNil(t, res)
	require.True(t, res.Equal(exp))

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint32()
		r := rand.Uint32()
		e := uint64(l) * uint64(r)
		lhs.SetUint64(uint64(l))
		rhs.SetUint64(uint64(r))
		exp.SetUint64(e)

		a := new(fq.Fq).Mul(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqDouble(t *testing.T) {
	t.Parallel()
	a := new(fq.Fq).SetUint64(2)
	e := new(fq.Fq).SetUint64(4)
	require.Equal(t, e, new(fq.Fq).Double(a))

	for i := 0; i < 25; i++ {
		tv := rand.Uint32()
		ttv := uint64(tv) * 2
		a = new(fq.Fq).SetUint64(uint64(tv))
		e = new(fq.Fq).SetUint64(ttv)
		require.Equal(t, e, new(fq.Fq).Double(a))
	}
}

func TestFqSquare(t *testing.T) {
	t.Parallel()
	a := new(fq.Fq).SetUint64(4)
	e := new(fq.Fq).SetUint64(16)
	require.Equal(t, e, a.Square(a))

	for i := 0; i < 25; i++ {
		j := rand.Uint32()
		exp := uint64(j) * uint64(j)
		e.SetUint64(exp)
		a.SetUint64(uint64(j))
		require.Equal(t, e, a.Square(a))
	}
}

func TestFqNeg(t *testing.T) {
	t.Parallel()
	var randomBytes [64]byte
	_, err := io.ReadFull(crand.Reader, randomBytes[:])
	require.NoError(t, err)
	fqRandom := new(fq.Fq).SetBytesWide(&randomBytes)
	require.NotNil(t, fqRandom)

	fqRandomNeg := new(fq.Fq).Neg(fqRandom)
	require.NotNil(t, fqRandomNeg)

	sum := new(fq.Fq).Add(fqRandomNeg, fqRandom)
	require.NotNil(t, sum)
	require.True(t, sum.IsZero())
}

func TestFqExp(t *testing.T) {
	t.Parallel()
	e := new(fq.Fq).SetUint64(8)
	a := new(fq.Fq).SetUint64(2)
	by := new(fq.Fq).SetUint64(3)
	require.Equal(t, a.Exp(a, by), e)
}

func TestFqSqrt(t *testing.T) {
	t.Parallel()
	t1 := new(fq.Fq).SetUint64(2)
	t2 := new(fq.Fq).Neg(t1)
	t3 := new(fq.Fq).Square(t1)
	_, wasSquare := t3.Sqrt(t3)
	require.True(t, wasSquare)
	require.True(t, t1.Equal(t3) || t2.Equal(t3))
	t1.SetUint64(5)
	_, wasSquare = new(fq.Fq).Sqrt(t1)
	require.False(t, wasSquare)
}

func TestFqInvert(t *testing.T) {
	t.Parallel()
	twoInv := new(fq.Fq).SetRaw(&[4]uint64{0xc623759080000001, 0x11234c7e04ca546e, 0x0000000000000000, 0x2000000000000000})
	two := new(fq.Fq).SetUint64(2)
	a, inverted := new(fq.Fq).Invert(two)
	require.True(t, inverted)
	require.Equal(t, a, twoInv)

	rootOfUnity := new(fq.Fq).SetRaw(&[4]uint64{0xa70e2c1102b6d05f, 0x9bb97ea3c106f049, 0x9e5c4dfd492ae26e, 0x2de6a9b8746d3f58})
	rootOfUnityInv := new(fq.Fq).SetRaw(&[4]uint64{0x57eecda0a84b6836, 0x4ad38b9084b8a80c, 0xf4c8f353124086c1, 0x2235e1a7415bf936})

	a, inverted = new(fq.Fq).Invert(rootOfUnity)
	require.True(t, inverted)
	require.Equal(t, a, rootOfUnityInv)

	lhs := new(fq.Fq).SetUint64(9)
	rhs := new(fq.Fq).SetUint64(3)
	rhsInv, inverted := new(fq.Fq).Invert(rhs)
	require.True(t, inverted)
	require.Equal(t, rhs, new(fq.Fq).Mul(lhs, rhsInv))

	rhs.SetZero()
	_, inverted = new(fq.Fq).Invert(rhs)
	require.False(t, inverted)
}

func TestFqCMove(t *testing.T) {
	t.Parallel()
	t1 := new(fq.Fq).SetUint64(5)
	t2 := new(fq.Fq).SetUint64(10)
	require.Equal(t, t1, new(fq.Fq).CMove(t1, t2, 0))
	require.Equal(t, t2, new(fq.Fq).CMove(t1, t2, 1))
}

func TestFqBytes(t *testing.T) {
	t.Parallel()
	t1 := new(fq.Fq).SetUint64(99)
	seq := t1.Bytes()
	t2, err := new(fq.Fq).SetBytes(&seq)
	require.NoError(t, err)
	require.Equal(t, t1, t2)

	for i := 0; i < 25; i++ {
		t1.SetUint64(rand.Uint64())
		seq = t1.Bytes()
		_, err = t2.SetBytes(&seq)
		require.NoError(t, err)
		require.Equal(t, t1, t2)
	}
}

func TestFqBigInt(t *testing.T) {
	t.Parallel()
	t1 := new(fq.Fq).SetNat(new(saferith.Nat).SetUint64(9999))
	t2 := new(fq.Fq).SetNat(t1.Nat())
	require.Equal(t, t1, t2)

	e := &fq.Fq{0x7bb1416dea3d6ae3, 0x62f9108a340aa525, 0x303b3f30fcaa477f, 0x11c9ef5422d80a4d}
	b := new(saferith.Nat).SetBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	t1.SetNat(b)
	require.Equal(t, e, t1)
	e[0] = 0x1095a9b315c2951e
	e[1] = 0xbf4d8871d58a03b8
	e[2] = 0xcfc4c0cf0355b880
	e[3] = 0x2e3610abdd27f5b2
	b.ModNeg(b, fq.Modulus)
	t1.SetNat(b)
	require.Equal(t, e, t1)
}

func TestFqSetBool(t *testing.T) {
	t.Parallel()
	require.Equal(t, new(fq.Fq).SetOne(), new(fq.Fq).SetBool(true))
	require.Equal(t, new(fq.Fq).SetZero(), new(fq.Fq).SetBool(false))
}

func TestFqSetBytesWide(t *testing.T) {
	t.Parallel()
	e := new(fq.Fq).SetRaw(&[4]uint64{0xe22bd0d1b22cc43e, 0x6b84e5b52490a7c8, 0x264262941ac9e229, 0x27dcfdf361ce4254})
	a := new(fq.Fq).SetBytesWide(&[64]byte{
		0x69, 0x23, 0x5a, 0x0b, 0xce, 0x0c, 0xa8, 0x64,
		0x3c, 0x78, 0xbc, 0x01, 0x05, 0xef, 0xf2, 0x84,
		0xde, 0xbb, 0x6b, 0xc8, 0x63, 0x5e, 0x6e, 0x69,
		0x62, 0xcc, 0xc6, 0x2d, 0xf5, 0x72, 0x40, 0x92,
		0x28, 0x11, 0xd6, 0xc8, 0x07, 0xa5, 0x88, 0x82,
		0xfe, 0xe3, 0x97, 0xf6, 0x1e, 0xfb, 0x2e, 0x3b,
		0x27, 0x5f, 0x85, 0x06, 0x8d, 0x99, 0xa4, 0x75,
		0xc0, 0x2c, 0x71, 0x69, 0x9e, 0x58, 0xea, 0x52,
	})
	require.Equal(t, e, a)
}

func TestFqCmp(t *testing.T) {
	t.Parallel()
	const n = 256
	for range n {
		xInt, err := crand.Int(crand.Reader, fq.Modulus.Big())
		require.NoError(t, err)
		xNat := new(saferith.Nat).SetBig(xInt, 255)
		x := new(fq.Fq).SetNat(xNat)
		yInt, err := crand.Int(crand.Reader, fq.Modulus.Big())
		require.NoError(t, err)
		yNat := new(saferith.Nat).SetBig(yInt, 255)
		y := new(fq.Fq).SetNat(yNat)

		expected := xInt.Cmp(yInt)
		actual := x.Cmp(y)
		require.Equal(t, expected, actual)
	}
}
