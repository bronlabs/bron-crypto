package fp_test

import (
	crand "crypto/rand"
	"io"
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pallas/impl/fp"
)

func TestFpSetOne(t *testing.T) {
	t.Parallel()

	fpOne := new(fp.Fp).SetOne()
	require.NotNil(t, fpOne)

	var fpRandom *fp.Fp
	for fpRandom == nil || fpRandom.IsZero() {
		var randomBytes [64]byte
		_, err := io.ReadFull(crand.Reader, randomBytes[:])
		require.NoError(t, err)
		fpRandom = new(fp.Fp).SetBytesWide(&randomBytes)
	}
	require.NotNil(t, fpRandom)
	require.False(t, fpRandom.IsZero())

	fpOneTimesRandom := new(fp.Fp).Mul(fpOne, fpRandom)
	require.NotNil(t, fpOneTimesRandom)
	require.True(t, fpRandom.Equal(fpOneTimesRandom))
}

func TestFpSetUint64(t *testing.T) {
	t.Parallel()
	act := new(fp.Fp).SetUint64(1 << 60)
	require.NotNil(t, act)
	// Remember it will be in montgomery form
	require.Equal(t, int64(0x592d30ed00000001), int64(act[0]))
}

func TestFpAdd(t *testing.T) {
	t.Parallel()
	lhs := new(fp.Fp).SetOne()
	rhs := new(fp.Fp).SetOne()
	exp := new(fp.Fp).SetUint64(2)
	res := new(fp.Fp).Add(lhs, rhs)
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

		a := new(fp.Fp).Add(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFpSub(t *testing.T) {
	t.Parallel()
	lhs := new(fp.Fp).SetOne()
	rhs := new(fp.Fp).SetOne()
	exp := new(fp.Fp).SetZero()
	res := new(fp.Fp).Sub(lhs, rhs)
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

		a := new(fp.Fp).Sub(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFpMul(t *testing.T) {
	t.Parallel()
	lhs := new(fp.Fp).SetOne()
	rhs := new(fp.Fp).SetOne()
	exp := new(fp.Fp).SetOne()
	res := new(fp.Fp).Mul(lhs, rhs)
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

		a := new(fp.Fp).Mul(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFpDouble(t *testing.T) {
	t.Parallel()
	a := new(fp.Fp).SetUint64(2)
	e := new(fp.Fp).SetUint64(4)
	require.Equal(t, e, new(fp.Fp).Double(a))

	for i := 0; i < 25; i++ {
		tv := rand.Uint32()
		ttv := uint64(tv) * 2
		a = new(fp.Fp).SetUint64(uint64(tv))
		e = new(fp.Fp).SetUint64(ttv)
		require.Equal(t, e, new(fp.Fp).Double(a))
	}
}

func TestFpSquare(t *testing.T) {
	t.Parallel()
	a := new(fp.Fp).SetUint64(4)
	e := new(fp.Fp).SetUint64(16)
	require.Equal(t, e, a.Square(a))

	for i := 0; i < 25; i++ {
		j := rand.Uint32()
		exp := uint64(j) * uint64(j)
		e.SetUint64(exp)
		a.SetUint64(uint64(j))
		require.Equal(t, e, a.Square(a))
	}
}

func TestFpNeg(t *testing.T) {
	t.Parallel()
	var randomBytes [64]byte
	_, err := io.ReadFull(crand.Reader, randomBytes[:])
	require.NoError(t, err)
	fpRandom := new(fp.Fp).SetBytesWide(&randomBytes)
	require.NotNil(t, fpRandom)

	fpRandomNeg := new(fp.Fp).Neg(fpRandom)
	require.NotNil(t, fpRandomNeg)

	sum := new(fp.Fp).Add(fpRandomNeg, fpRandom)
	require.NotNil(t, sum)
	require.True(t, sum.IsZero())
}

func TestFpExp(t *testing.T) {
	t.Parallel()
	e := new(fp.Fp).SetUint64(8)
	a := new(fp.Fp).SetUint64(2)
	by := new(fp.Fp).SetUint64(3)
	require.Equal(t, a.Exp(a, by), e)
}

func TestFpSqrt(t *testing.T) {
	t.Parallel()
	t1 := new(fp.Fp).SetUint64(2)
	t2 := new(fp.Fp).Neg(t1)
	t3 := new(fp.Fp).Square(t1)
	_, wasSquare := t3.Sqrt(t3)
	require.True(t, wasSquare)
	require.True(t, t1.Equal(t3) || t2.Equal(t3))
	t1.SetUint64(5)
	_, wasSquare = new(fp.Fp).Sqrt(t1)
	require.False(t, wasSquare)
}

func TestFpInvert(t *testing.T) {
	t.Parallel()
	var fpRandom *fp.Fp
	for fpRandom == nil || fpRandom.IsZero() {
		var randomBytes [64]byte
		_, err := io.ReadFull(crand.Reader, randomBytes[:])
		require.NoError(t, err)
		fpRandom = new(fp.Fp).SetBytesWide(&randomBytes)
	}
	require.NotNil(t, fpRandom)
	require.False(t, fpRandom.IsZero())

	fpRandomInv, wasInverted := new(fp.Fp).Invert(fpRandom)
	require.NotNil(t, fpRandomInv)
	require.True(t, wasInverted)

	prod := new(fp.Fp).Mul(fpRandomInv, fpRandom)
	require.NotNil(t, prod)
	require.True(t, prod.IsOne())
}

func TestFpCMove(t *testing.T) {
	t.Parallel()
	t1 := new(fp.Fp).SetUint64(5)
	t2 := new(fp.Fp).SetUint64(10)
	require.Equal(t, t1, new(fp.Fp).CMove(t1, t2, 0))
	require.Equal(t, t2, new(fp.Fp).CMove(t1, t2, 1))
}

func TestFpBytes(t *testing.T) {
	t.Parallel()
	t1 := new(fp.Fp).SetUint64(99)
	seq := t1.Bytes()
	t2, err := new(fp.Fp).SetBytes(&seq)
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

func TestFpBigInt(t *testing.T) {
	t.Parallel()
	t1 := new(fp.Fp).SetNat(new(saferith.Nat).SetUint64(9999))
	t2 := new(fp.Fp).SetNat(t1.Nat())
	require.Equal(t, t1, t2)

	e := &fp.Fp{0x8c6bc70550c87761, 0xce2c6c48e7063731, 0xf1275fd1e4607cd6, 0x3e6762e63501edbd}
	b := new(saferith.Nat).SetBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	t1.SetNat(b)
	require.Equal(t, e, t1)
	e[0] = 0xcc169e7af3788a0
	e[1] = 0x541a2cb32246c1ea
	e[2] = 0xed8a02e1b9f8329
	e[3] = 0x1989d19cafe1242
	b.ModNeg(b, fp.Modulus)
	t1.SetNat(b)
	require.Equal(t, e, t1)
}

func TestFpSetBool(t *testing.T) {
	t.Parallel()
	require.Equal(t, new(fp.Fp).SetOne(), new(fp.Fp).SetBool(true))
	require.Equal(t, new(fp.Fp).SetZero(), new(fp.Fp).SetBool(false))
}

func TestFpSetBytesWide(t *testing.T) {
	t.Parallel()
	e := new(fp.Fp).SetRaw(&[4]uint64{0x3daec14d565241d9, 0x0b7af45b6073944b, 0xea5b8bd611a5bd4c, 0x150160330625db3d})
	a := new(fp.Fp).SetBytesWide(&[64]byte{
		0xa1, 0x78, 0x76, 0x29, 0x41, 0x56, 0x15, 0xee,
		0x65, 0xbe, 0xfd, 0xdb, 0x6b, 0x15, 0x3e, 0xd8,
		0xb5, 0xa0, 0x8b, 0xc6, 0x34, 0xd8, 0xcc, 0xd9,
		0x58, 0x27, 0x27, 0x12, 0xe3, 0xed, 0x08, 0xf5,
		0x89, 0x8e, 0x22, 0xf8, 0xcb, 0xf7, 0x8d, 0x03,
		0x41, 0x4b, 0xc7, 0xa3, 0xe4, 0xa1, 0x05, 0x35,
		0xb3, 0x2d, 0xb8, 0x5e, 0x77, 0x6f, 0xa4, 0xbf,
		0x1d, 0x47, 0x2f, 0x26, 0x7e, 0xe2, 0xeb, 0x26,
	})
	require.Equal(t, e, a)
}

func TestFpCmp(t *testing.T) {
	t.Parallel()
	const n = 256
	for range n {
		xInt, err := crand.Int(crand.Reader, fp.Modulus.Big())
		require.NoError(t, err)
		xNat := new(saferith.Nat).SetBig(xInt, 255)
		x := new(fp.Fp).SetNat(xNat)
		yInt, err := crand.Int(crand.Reader, fp.Modulus.Big())
		require.NoError(t, err)
		yNat := new(saferith.Nat).SetBig(yInt, 255)
		y := new(fp.Fp).SetNat(yNat)

		expected := xInt.Cmp(yInt)
		actual := x.Cmp(y)
		require.Equal(t, expected, actual)
	}
}
