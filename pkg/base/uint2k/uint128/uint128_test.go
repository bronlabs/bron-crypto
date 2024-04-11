package uint128

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"

	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var mod2Pow128 = saferith.ModulusFromNat(new(saferith.Nat).Lsh(saferithUtils.NatOne, 128, -1))

func randUint128() Uint128 {
	randBuf := make([]byte, 16)
	crand.Read(randBuf)
	return NewFromBytesLE(randBuf)
}

func TestUint128(t *testing.T) {
	t.Parallel()

	// test non-arithmetic methods.
	for i := 0; i < 1000; i++ {
		x, y := randUint128(), randUint128()
		// Shifting.
		if i%3 == 0 {
			x = x.Rsh(64)
		} else if i%7 == 0 {
			x = x.Lsh(64)
		}
		// Conversions.
		b := make([]byte, 16)
		x.PutBytesLE(b)
		if NewFromBytesLE(b) != x {
			t.Fatal("FromBytes is not the inverse of PutBytes for", x)
		}
		x.PutBytesBE(b)
		if NewFromBytesBE(b) != x {
			t.Fatal("FromBytes is not the inverse of PutBytes for", x)
		}
		// Conversion to/From SaferithNat.
		if NewFromNat(x.Nat()) != x {
			t.Fatal("ToNat is not the inverse of ToUint128 for", x)
		}
		// Compare.
		if !x.Equals(x) {
			t.Fatalf("%v does not equal itself", x.Lo)
		}

		// ConstantTimeSelect
		if ConstantTimeSelect(true, x, y) != x {
			t.Fatalf("ConstantTimeSelect(true, %v, %v) should equal %v, got %v", x, y, x, ConstantTimeSelect(true, x, y))
		}
		if ConstantTimeSelect(false, x, y) != y {
			t.Fatalf("ConstantTimeSelect(false, %v, %v) should equal %v, got %v", x, y, y, ConstantTimeSelect(false, x, y))
		}

		if x.Cmp(y) != x.Nat().Big().Cmp(y.Nat().Big()) {
			t.Fatalf("mismatch: cmp(%v,%v) should equal %v, got %v", x, y, x.Nat().Big().Cmp(y.Nat().Big()), x.Cmp(y))
		} else if x.Cmp(x) != 0 {
			t.Fatalf("%v does not equal itself", x)
		}
	}

	// Check FromBig panics.
	checkPanic := func(fn func(), msg string) {
		defer func() {
			r := recover()
			if s, ok := r.(string); !ok || s != msg {
				t.Errorf("expected %q, got %q", msg, r)
			}
		}()
		fn()
	}
	checkPanic(func() { _ = FromBig(big.NewInt(-1)) }, "value cannot be negative")
	checkPanic(func() { _ = FromBig(new(big.Int).Lsh(big.NewInt(1), 129)) }, "value overflows Uint128")
}

func TestArithmetic(t *testing.T) {
	t.Parallel()

	// compare Uint128 arithmetic methods to their math/big equivalents, using
	// random values
	randBuf := make([]byte, 17)
	randUint128 := func() Uint128 {
		crand.Read(randBuf)
		var Lo, Hi uint64
		if randBuf[16]&1 != 0 {
			Lo = binary.LittleEndian.Uint64(randBuf[:8])
		}
		if randBuf[16]&2 != 0 {
			Hi = binary.LittleEndian.Uint64(randBuf[8:])
		}
		return New(Lo, Hi)
	}
	mod128 := func(i *big.Int) *big.Int {
		// wraparound semantics
		if i.Sign() == -1 {
			i = i.Add(new(big.Int).Lsh(big.NewInt(1), 128), i)
		}
		_, rem := i.QuoRem(i, new(big.Int).Lsh(big.NewInt(1), 128), new(big.Int))
		return rem
	}
	mod128nat := func(i *saferith.Nat) (r *saferith.Nat) {
		// wraparound semantics
		return new(saferith.Nat).Mod(i, mod2Pow128)
	}
	checkArithOp := func(x Uint128, op string, y Uint128, fn func(x, y Uint128) Uint128, fnb func(z, x, y *saferith.Nat, _ int) *saferith.Nat) {
		t.Helper()
		r := fn(x, y)
		rb := mod128nat(fnb(new(saferith.Nat), x.Nat(), y.Nat(), -1))
		if r.Nat().Eq(rb) != 1 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, y, rb, r)
		}
	}
	checkBinOp := func(x Uint128, op string, y Uint128, fn func(x, y Uint128) Uint128, fnb func(z, x, y *big.Int) *big.Int) {
		t.Helper()
		r := fn(x, y)
		rb := mod128(fnb(new(big.Int), x.Nat().Big(), y.Nat().Big()))
		if r.Nat().Big().Cmp(rb) != 0 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, y, rb, r)
		}
	}
	checkShiftOp := func(x Uint128, op string, n uint, fn func(x Uint128, n uint) Uint128, fnb func(z, x *big.Int, n uint) *big.Int) {
		t.Helper()
		r := fn(x, n)
		rb := mod128(fnb(new(big.Int), x.Nat().Big(), n))
		if r.Nat().Big().Cmp(rb) != 0 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, n, rb, r)
		}
	}
	for i := 0; i < 1000; i++ {
		x, y, z := randUint128(), randUint128(), uint(randUint128().Lo&0xFF)
		checkArithOp(x, "+", y, Uint128.Add, (*saferith.Nat).Add)
		checkArithOp(x, "-", y, Uint128.Sub, (*saferith.Nat).Sub)
		checkArithOp(x, "*", y, Uint128.Mul, (*saferith.Nat).Mul)
		checkBinOp(x, "&", y, Uint128.And, (*big.Int).And)
		checkBinOp(x, "|", y, Uint128.Or, (*big.Int).Or)
		checkBinOp(x, "^", y, Uint128.Xor, (*big.Int).Xor)
		checkShiftOp(x, "<<", z, Uint128.Lsh, (*big.Int).Lsh)
		checkShiftOp(x, ">>", z, Uint128.Rsh, (*big.Int).Rsh)
	}
}

var result Uint128

var resultNat *saferith.Nat

func BenchmarkUint128Add(b *testing.B) {
	var r Uint128
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		x, y := randUint128(), randUint128()
		b.StartTimer()
		r = x.Add(y)
	}
	result = r
}

func BenchmarkSaferith128NatAdd(b *testing.B) {
	var r *saferith.Nat
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		x, y := randUint128().Nat(), randUint128().Nat()
		b.StartTimer()
		r = x.Add(x, y, 128)
	}
	resultNat = r
}
