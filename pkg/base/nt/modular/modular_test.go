package modular_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// bigModExp is a reference implementation using big.Int
func bigModExp(base, exp, mod int64) int64 {
	return new(big.Int).Exp(big.NewInt(base), big.NewInt(exp), big.NewInt(mod)).Int64()
}

// SimpleModulus tests

func TestNewSimple(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(35)
	m, _ := numct.NewModulus(n)

	simple, ok := modular.NewSimple(m)
	require.Equal(t, ct.True, ok)
	require.NotNil(t, simple)
	require.Equal(t, int64(35), simple.Modulus().Big().Int64())
}

func TestNewSimple_Nil(t *testing.T) {
	t.Parallel()
	_, ok := modular.NewSimple(nil)
	require.Equal(t, ct.False, ok)
}

func TestSimpleModulus_ModMul(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(35)
	m, _ := numct.NewModulus(n)
	simple, _ := modular.NewSimple(m)

	a := numct.NewNat(6)
	b := numct.NewNat(7)
	var out numct.Nat
	simple.ModMul(&out, a, b)

	// 6 * 7 = 42 mod 35 = 7
	require.Equal(t, int64(7), out.Big().Int64())
}

func TestSimpleModulus_ModExp(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(35)
	m, _ := numct.NewModulus(n)
	simple, _ := modular.NewSimple(m)

	base := numct.NewNat(2)
	exp := numct.NewNat(10)
	var out numct.Nat
	simple.ModExp(&out, base, exp)

	require.Equal(t, bigModExp(2, 10, 35), out.Big().Int64())
}

func TestSimpleModulus_ModInv(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(35)
	m, _ := numct.NewModulus(n)
	simple, _ := modular.NewSimple(m)

	a := numct.NewNat(3)
	var inv numct.Nat
	ok := simple.ModInv(&inv, a)
	require.Equal(t, ct.True, ok)

	// Verify: 3 * inv mod 35 = 1
	var check numct.Nat
	simple.ModMul(&check, a, &inv)
	require.Equal(t, int64(1), check.Big().Int64())
}

func TestSimpleModulus_ModDiv(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(35)
	m, _ := numct.NewModulus(n)
	simple, _ := modular.NewSimple(m)

	a := numct.NewNat(21)
	b := numct.NewNat(3)
	var out numct.Nat
	ok := simple.ModDiv(&out, a, b)
	require.Equal(t, ct.True, ok)

	// 21 / 3 mod 35 = 7
	require.Equal(t, int64(7), out.Big().Int64())
}

func TestSimpleModulus_Lift(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(35)
	m, _ := numct.NewModulus(n)
	simple, _ := modular.NewSimple(m)

	lifted, ok := simple.Lift()
	require.Equal(t, ct.True, ok)
	require.Equal(t, int64(35*35), lifted.Modulus().Big().Int64())
}

// OddPrimeFactors tests

func TestNewOddPrimeFactors(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)

	opf, ok := modular.NewOddPrimeFactors(p, q)
	require.Equal(t, ct.True, ok)
	require.NotNil(t, opf)
	require.Equal(t, int64(35), opf.Modulus().Big().Int64())
}

func TestNewOddPrimeFactors_SamePrime(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	_, ok := modular.NewOddPrimeFactors(p, p)
	require.Equal(t, ct.False, ok)
}

func TestNewOddPrimeFactors_NotPrime(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(6) // not prime
	_, ok := modular.NewOddPrimeFactors(p, q)
	require.Equal(t, ct.False, ok)
}

func TestNewOddPrimeFactors_EvenPrime(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(2) // even
	q := numct.NewNat(5)
	_, ok := modular.NewOddPrimeFactors(p, q)
	require.Equal(t, ct.False, ok)
}

func TestOddPrimeFactors_ModMul(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	a := numct.NewNat(6)
	b := numct.NewNat(7)
	var out numct.Nat
	opf.ModMul(&out, a, b)

	require.Equal(t, int64(7), out.Big().Int64()) // 42 mod 35 = 7
}

func TestOddPrimeFactors_ModExp_Coprime(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	// Test with coprime base
	base := numct.NewNat(2)
	exp := numct.NewNat(100)
	var out numct.Nat
	opf.ModExp(&out, base, exp)

	require.Equal(t, bigModExp(2, 100, 35), out.Big().Int64())
}

func TestOddPrimeFactors_ModExp_NonCoprime(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	// Test with non-coprime base (base = 5, shares factor with n=35)
	base := numct.NewNat(5)
	exp := numct.NewNat(100)
	var out numct.Nat
	opf.ModExp(&out, base, exp)

	require.Equal(t, bigModExp(5, 100, 35), out.Big().Int64())
}

func TestOddPrimeFactors_ModExp_NonCoprime_7(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	// Test with non-coprime base (base = 7, shares factor with n=35)
	base := numct.NewNat(7)
	exp := numct.NewNat(50)
	var out numct.Nat
	opf.ModExp(&out, base, exp)

	require.Equal(t, bigModExp(7, 50, 35), out.Big().Int64())
}

func TestOddPrimeFactors_ModExpI_Positive(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	base := numct.NewNat(2)
	exp := numct.NewIntFromBig(big.NewInt(10), 64)
	var out numct.Nat
	opf.ModExpI(&out, base, exp)

	require.Equal(t, bigModExp(2, 10, 35), out.Big().Int64())
}

func TestOddPrimeFactors_ModExpI_Negative(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	base := numct.NewNat(2)
	exp := numct.NewIntFromBig(big.NewInt(-1), 64)
	var out numct.Nat
	opf.ModExpI(&out, base, exp)

	// 2^{-1} mod 35 = inverse of 2 mod 35 = 18 (since 2*18 = 36 ≡ 1 mod 35)
	require.Equal(t, int64(18), out.Big().Int64())
}

func TestOddPrimeFactors_ModInv(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	a := numct.NewNat(3)
	var inv numct.Nat
	ok := opf.ModInv(&inv, a)
	require.Equal(t, ct.True, ok)

	// Verify: 3 * inv mod 35 = 1
	var check numct.Nat
	opf.ModMul(&check, a, &inv)
	require.Equal(t, int64(1), check.Big().Int64())
}

func TestOddPrimeFactors_ModInv_NonInvertible(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	// 5 is not invertible mod 35 (gcd(5, 35) = 5 ≠ 1)
	a := numct.NewNat(5)
	var inv numct.Nat
	ok := opf.ModInv(&inv, a)
	require.Equal(t, ct.False, ok)
}

func TestOddPrimeFactors_ModDiv(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	a := numct.NewNat(21)
	b := numct.NewNat(3)
	var out numct.Nat
	ok := opf.ModDiv(&out, a, b)
	require.Equal(t, ct.True, ok)
	require.Equal(t, int64(7), out.Big().Int64())
}

func TestOddPrimeFactors_MultiBaseExp(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	bases := []*numct.Nat{numct.NewNat(2), numct.NewNat(3), numct.NewNat(5)}
	exp := numct.NewNat(10)
	out := make([]*numct.Nat, 3)
	for i := range out {
		out[i] = numct.NewNat(0)
	}

	opf.MultiBaseExp(out, bases, exp)

	require.Equal(t, bigModExp(2, 10, 35), out[0].Big().Int64())
	require.Equal(t, bigModExp(3, 10, 35), out[1].Big().Int64())
	require.Equal(t, bigModExp(5, 10, 35), out[2].Big().Int64())
}

func TestOddPrimeFactors_Lift(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	lifted, ok := opf.Lift()
	require.Equal(t, ct.True, ok)
	require.Equal(t, int64(35*35), lifted.Modulus().Big().Int64())
}

// OddPrimeSquare tests

func TestNewOddPrimeSquare(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)

	ops, ok := modular.NewOddPrimeSquare(p)
	require.Equal(t, ct.True, ok)
	require.NotNil(t, ops)
	require.Equal(t, int64(25), ops.Modulus().Big().Int64())
}

func TestNewOddPrimeSquare_NotPrime(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(6)
	_, ok := modular.NewOddPrimeSquare(p)
	require.Equal(t, ct.False, ok)
}

func TestNewOddPrimeSquare_Even(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(2)
	_, ok := modular.NewOddPrimeSquare(p)
	require.Equal(t, ct.False, ok)
}

// OddPrimeSquareFactors tests

func TestNewOddPrimeSquareFactors(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)

	opsf, ok := modular.NewOddPrimeSquareFactors(p, q)
	require.Equal(t, ct.True, ok)
	require.NotNil(t, opsf)
	// n^2 = (5*7)^2 = 35^2 = 1225
	require.Equal(t, int64(1225), opsf.Modulus().Big().Int64())
}

func TestNewOddPrimeSquareFactors_SamePrime(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	_, ok := modular.NewOddPrimeSquareFactors(p, p)
	require.Equal(t, ct.False, ok)
}

func TestOddPrimeSquareFactors_ModMul(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opsf, _ := modular.NewOddPrimeSquareFactors(p, q)

	a := numct.NewNat(100)
	b := numct.NewNat(200)
	var out numct.Nat
	opsf.ModMul(&out, a, b)

	// 100 * 200 = 20000 mod 1225 = 20000 - 16*1225 = 20000 - 19600 = 400
	require.Equal(t, int64(400), out.Big().Int64())
}

func TestOddPrimeSquareFactors_ModExp_Coprime(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opsf, _ := modular.NewOddPrimeSquareFactors(p, q)

	base := numct.NewNat(2)
	exp := numct.NewNat(100)
	var out numct.Nat
	opsf.ModExp(&out, base, exp)

	require.Equal(t, bigModExp(2, 100, 1225), out.Big().Int64())
}

func TestOddPrimeSquareFactors_ModExp_NonCoprime(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opsf, _ := modular.NewOddPrimeSquareFactors(p, q)

	// Test with non-coprime base
	base := numct.NewNat(5)
	exp := numct.NewNat(50)
	var out numct.Nat
	opsf.ModExp(&out, base, exp)

	require.Equal(t, bigModExp(5, 50, 1225), out.Big().Int64())
}

func TestOddPrimeSquareFactors_ModInv(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opsf, _ := modular.NewOddPrimeSquareFactors(p, q)

	a := numct.NewNat(3)
	var inv numct.Nat
	ok := opsf.ModInv(&inv, a)
	require.Equal(t, ct.True, ok)

	// Verify: 3 * inv mod 1225 = 1
	var check numct.Nat
	opsf.ModMul(&check, a, &inv)
	require.Equal(t, int64(1), check.Big().Int64())
}

func TestOddPrimeSquareFactors_ModDiv(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opsf, _ := modular.NewOddPrimeSquareFactors(p, q)

	a := numct.NewNat(21)
	b := numct.NewNat(3)
	var out numct.Nat
	ok := opsf.ModDiv(&out, a, b)
	require.Equal(t, ct.True, ok)
	require.Equal(t, int64(7), out.Big().Int64())
}

func TestOddPrimeSquareFactors_MultiBaseExp(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opsf, _ := modular.NewOddPrimeSquareFactors(p, q)

	bases := []*numct.Nat{numct.NewNat(2), numct.NewNat(3), numct.NewNat(5)}
	exp := numct.NewNat(10)
	out := make([]*numct.Nat, 3)
	for i := range out {
		out[i] = numct.NewNat(0)
	}

	opsf.MultiBaseExp(out, bases, exp)

	require.Equal(t, bigModExp(2, 10, 1225), out[0].Big().Int64())
	require.Equal(t, bigModExp(3, 10, 1225), out[1].Big().Int64())
	require.Equal(t, bigModExp(5, 10, 1225), out[2].Big().Int64())
}

func TestOddPrimeSquareFactors_ExpToN(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opsf, _ := modular.NewOddPrimeSquareFactors(p, q)

	// n = 35, n^2 = 1225
	// Test: a^n mod n^2
	a := numct.NewNat(2)
	var out numct.Nat
	opsf.ExpToN(&out, a)

	require.Equal(t, bigModExp(2, 35, 1225), out.Big().Int64())
}

// Interface compliance tests

func TestArithmeticInterface_SimpleModulus(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(35)
	m, _ := numct.NewModulus(n)
	simple, _ := modular.NewSimple(m)

	var arith modular.Arithmetic = simple
	require.NotNil(t, arith.Modulus())
	require.NotNil(t, arith.MultiplicativeOrder())
}

func TestArithmeticInterface_OddPrimeFactors(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opf, _ := modular.NewOddPrimeFactors(p, q)

	var arith modular.Arithmetic = opf
	require.NotNil(t, arith.Modulus())
	require.NotNil(t, arith.MultiplicativeOrder())
}

func TestArithmeticInterface_OddPrimeSquareFactors(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	opsf, _ := modular.NewOddPrimeSquareFactors(p, q)

	var arith modular.Arithmetic = opsf
	require.NotNil(t, arith.Modulus())
	require.NotNil(t, arith.MultiplicativeOrder())
}
