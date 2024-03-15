package uints

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

func randUint256(t require.TestingT) U256 {
	randBuf := make([]byte, 32)
	_, err := io.ReadFull(crand.Reader, randBuf)
	require.NoError(t, err)
	return NewU256FromBytesLE(randBuf)
}

func TestUint256(t *testing.T) {
	t.Parallel()

	// test non-arithmetic methods.
	for i := 0; i < 1000; i++ {
		x, y := randUint256(t), randUint256(t)
		// Shifting.
		if i%3 == 0 {
			x = x.Rsh(64)
		} else if i%7 == 0 {
			x = x.Lsh(64)
		}

		// Conversion to/From SaferithNat.
		if NewU256FromNat(x.Nat()) != x {
			t.Fatal("ToNat is not the inverse of ToU256 for", x)
		}
		// Compare.
		if !x.Equals(x) {
			t.Fatalf("%v does not equal itself", x.Limb0)
		}

		if ConstantTimeU256Select(1, x, y) != x {
			t.Fatalf("ConstantTimeU256Select(true, %v, %v) should equal %v, got %v", x, y, x, ConstantTimeU256Select(1, x, y))
		}
		if ConstantTimeU256Select(0, x, y) != y {
			t.Fatalf("ConstantTimeU256Select(false, %v, %v) should equal %v, got %v", x, y, y, ConstantTimeU256Select(0, x, y))
		}

		if x.Cmp(y) != x.Nat().Big().Cmp(y.Nat().Big()) {
			t.Fatalf("mismatch: cmp(%v,%v) should equal %v, got %v", x, y, x.Nat().Big().Cmp(y.Nat().Big()), x.Cmp(y))
		} else if x.Cmp(x) != 0 {
			t.Fatalf("%v does not equal itself", x)
		}
	}
}

func TestArithmeticUint256(t *testing.T) {
	t.Parallel()

	// compare U256 arithmetic methods to their math/big equivalents, using
	// random values
	randBuf := make([]byte, 33)
	randUint256 := func() U256 {
		_, err := io.ReadFull(crand.Reader, randBuf)
		require.NoError(t, err)

		var Lo, Hi uint64
		if randBuf[32]&1 != 0 {
			Lo = binary.LittleEndian.Uint64(randBuf[:8])
		}
		if randBuf[32]&2 != 0 {
			Hi = binary.LittleEndian.Uint64(randBuf[8:])
		}
		return U256{
			Limb0: Lo,
			Limb1: 0,
			Limb2: 0,
			Limb3: Hi,
		}
	}

	mod256 := func(i *big.Int) *big.Int {
		// wraparound semantics
		if i.Sign() == -1 {
			i = i.Add(new(big.Int).Lsh(big.NewInt(1), 256), i)
		}
		_, rem := i.QuoRem(i, new(big.Int).Lsh(big.NewInt(1), 256), new(big.Int))
		return rem
	}

	checkBinOp := func(x U256, op string, y U256, fn func(x, y U256) U256, fnb func(z, x, y *big.Int) *big.Int) {
		t.Helper()
		r := fn(x, y)
		rb := mod256(fnb(new(big.Int), x.Nat().Big(), y.Nat().Big()))
		if r.Nat().Big().Cmp(rb) != 0 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, y, rb, r)
		}
	}

	checkLeftShiftOp := func(x U256, op string, n uint, fn func(x U256, n uint) U256, _ func(z, x *big.Int, n uint) *big.Int) {
		t.Helper()
		r := fn(x, n)
		rb := new(saferith.Nat).Lsh(new(saferith.Nat).SetBytes(x.ToBytesBE()), n, 256)
		if _, eq, _ := r.Nat().Cmp(rb); eq != 1 {
			t.Fatalf("mismatch: %v %v %v should equal %v, got %v", x.Nat().Hex(), op, n, rb.Hex(), r.Nat().Hex())
		}
	}

	checkRightShiftOp := func(x U256, op string, n uint, fn func(x U256, n uint) U256, _ func(z, x *big.Int, n uint) *big.Int) {
		t.Helper()
		r := fn(x, n)
		rb := new(saferith.Nat).Rsh(new(saferith.Nat).SetBytes(x.ToBytesBE()), n, 256)
		if _, eq, _ := r.Nat().Cmp(rb); eq != 1 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, n, rb, r)
		}
	}

	for i := 0; i < 1000; i++ {
		x, y, z := randUint256(), randUint256(), uint(randUint256().Limb0&0xFF)
		checkBinOp(x, "+", y, U256.Add, (*big.Int).Add)
		checkBinOp(x, "-", y, U256.Sub, (*big.Int).Sub)
		checkBinOp(x, "*", y, U256.Mul, (*big.Int).Mul)
		checkBinOp(x, "&", y, U256.And, (*big.Int).And)
		checkBinOp(x, "|", y, U256.Or, (*big.Int).Or)
		checkBinOp(x, "^", y, U256.Xor, (*big.Int).Xor)
		checkLeftShiftOp(x, "<<", 64*3+1, U256.Lsh, (*big.Int).Lsh)
		checkRightShiftOp(x, ">>", z, U256.Rsh, (*big.Int).Rsh)
	}
}
