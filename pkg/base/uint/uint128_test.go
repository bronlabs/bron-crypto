package uint

import (
	crand "crypto/rand"
	"encoding/binary"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"testing"
)

func randUint128(t require.TestingT) U128 {
	randBuf := make([]byte, 16)
	_, err := io.ReadFull(crand.Reader, randBuf)
	require.NoError(t, err)
	return NewU128FromBytesLE(randBuf)
}

func TestUint128(t *testing.T) {
	t.Parallel()

	// test non-arithmetic methods.
	for i := 0; i < 1000; i++ {
		x, y := randUint128(t), randUint128(t)
		// Shifting.
		if i%3 == 0 {
			x = x.Rsh(64)
		} else if i%7 == 0 {
			x = x.Lsh(64)
		}

		// Conversion to/From SaferithNat.
		if NewU128FromNat(x.Nat()) != x {
			t.Fatal("ToNat is not the inverse of ToUint128 for", x)
		}
		// Compare.
		if !x.Equals(x) {
			t.Fatalf("%v does not equal itself", x.Lo)
		}

		// ConstantTimeU128Select
		if ConstantTimeU128Select(1, x, y) != x {
			t.Fatalf("ConstantTimeU128Select(true, %v, %v) should equal %v, got %v", x, y, x, ConstantTimeU128Select(1, x, y))
		}
		if ConstantTimeU128Select(0, x, y) != y {
			t.Fatalf("ConstantTimeU128Select(false, %v, %v) should equal %v, got %v", x, y, y, ConstantTimeU128Select(0, x, y))
		}

		if x.Cmp(y) != x.Nat().Big().Cmp(y.Nat().Big()) {
			t.Fatalf("mismatch: cmp(%v,%v) should equal %v, got %v", x, y, x.Nat().Big().Cmp(y.Nat().Big()), x.Cmp(y))
		} else if x.Cmp(x) != 0 {
			t.Fatalf("%v does not equal itself", x)
		}
	}

	// Check NewU128FromBig panics.
	checkPanic := func(fn func(), msg string) {
		defer func() {
			r := recover()
			if s, ok := r.(string); !ok || s != msg {
				t.Errorf("expected %q, got %q", msg, r)
			}
		}()
		fn()
	}
	checkPanic(func() { _ = NewU128FromBig(big.NewInt(-1)) }, "value cannot be negative")
	checkPanic(func() { _ = NewU128FromBig(new(big.Int).Lsh(big.NewInt(1), 129)) }, "value overflows U128")
}

func TestArithmeticUint128(t *testing.T) {
	t.Parallel()

	// compare U128 arithmetic methods to their math/big equivalents, using
	// random values
	randBuf := make([]byte, 17)
	randUint128 := func() U128 {
		_, err := io.ReadFull(crand.Reader, randBuf)
		require.NoError(t, err)

		var Lo, Hi uint64
		if randBuf[16]&1 != 0 {
			Lo = binary.LittleEndian.Uint64(randBuf[:8])
		}
		if randBuf[16]&2 != 0 {
			Hi = binary.LittleEndian.Uint64(randBuf[8:])
		}
		return NewU128(Lo, Hi)
	}
	mod128 := func(i *big.Int) *big.Int {
		// wraparound semantics
		if i.Sign() == -1 {
			i = i.Add(new(big.Int).Lsh(big.NewInt(1), 128), i)
		}
		_, rem := i.QuoRem(i, new(big.Int).Lsh(big.NewInt(1), 128), new(big.Int))
		return rem
	}
	checkBinOp := func(x U128, op string, y U128, fn func(x, y U128) U128, fnb func(z, x, y *big.Int) *big.Int) {
		t.Helper()
		r := fn(x, y)
		rb := mod128(fnb(new(big.Int), x.Nat().Big(), y.Nat().Big()))
		if r.Nat().Big().Cmp(rb) != 0 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, y, rb, r)
		}
	}
	checkShiftOp := func(x U128, op string, n uint, fn func(x U128, n uint) U128, fnb func(z, x *big.Int, n uint) *big.Int) {
		t.Helper()
		r := fn(x, n)
		rb := mod128(fnb(new(big.Int), x.Nat().Big(), n))
		if r.Nat().Big().Cmp(rb) != 0 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, n, rb, r)
		}
	}
	for i := 0; i < 1000; i++ {
		x, y, z := randUint128(), randUint128(), uint(randUint128().Lo&0xFF)
		checkBinOp(x, "+", y, U128.Add, (*big.Int).Add)
		checkBinOp(x, "-", y, U128.Sub, (*big.Int).Sub)
		checkBinOp(x, "*", y, U128.Mul, (*big.Int).Mul)
		checkBinOp(x, "&", y, U128.And, (*big.Int).And)
		checkBinOp(x, "|", y, U128.Or, (*big.Int).Or)
		checkBinOp(x, "^", y, U128.Xor, (*big.Int).Xor)
		checkShiftOp(x, "<<", z, U128.Lsh, (*big.Int).Lsh)
		checkShiftOp(x, ">>", z, U128.Rsh, (*big.Int).Rsh)
	}
}
