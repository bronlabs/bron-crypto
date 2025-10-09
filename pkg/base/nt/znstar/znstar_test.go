package znstar_test

// import (
// 	"crypto/rand"
// 	"math/big"
// 	"testing"

// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// )

// // TestNewUnitGroupOfUnknownOrder tests creating a unit group with unknown order
// func TestNewUnitGroupOfUnknownOrder(t *testing.T) {
// 	testCases := []struct {
// 		name    string
// 		modulus uint64
// 		wantErr bool
// 	}{
// 		{"modulus 15", 15, false},
// 		{"modulus 35", 35, false},
// 		{"modulus 77", 77, false},
// 		{"modulus 0", 0, true},
// 		{"modulus 1", 1, false}, // edge case, but valid mathematically
// 	}

// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			m, err := num.NPlus().FromUint64(tc.modulus)
// 			if tc.modulus == 0 {
// 				require.Error(t, err)
// 				return
// 			}
// 			require.NoError(t, err)

// 			type UnknownExp = *struct{}
// 			uzmod, err := znstar.NewUnitGroupOfUnknownOrder[UnknownExp](m)
// 			if tc.wantErr {
// 				assert.Error(t, err)
// 				return
// 			}
// 			require.NoError(t, err)
// 			assert.NotNil(t, uzmod)
// 			assert.Equal(t, cardinal.Unknown(), uzmod.Order())
// 			assert.Equal(t, m, uzmod.Modulus())
// 		})
// 	}
// }

// // TestNewRSAGroup tests creating an RSA group from two primes
// func TestNewRSAGroup(t *testing.T) {
// 	// Generate two small primes for testing
// 	p := num.N().FromUint64(7)
// 	q := num.N().FromUint64(11)

// 	t.Run("valid primes", func(t *testing.T) {
// 		rsaGroup, err := znstar.NewRSAGroup(p, q)
// 		require.NoError(t, err)
// 		assert.NotNil(t, rsaGroup)

// 		// Modulus should be p*q = 77
// 		expectedModulus, _ := num.NPlus().FromUint64(77)
// 		assert.True(t, expectedModulus.Equal(rsaGroup.Modulus()))
// 		assert.Equal(t, cardinal.Unknown(), rsaGroup.Order())
// 	})

// 	t.Run("nil p", func(t *testing.T) {
// 		_, err := znstar.NewRSAGroup(nil, q)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "must not be nil")
// 	})

// 	t.Run("nil q", func(t *testing.T) {
// 		_, err := znstar.NewRSAGroup(p, nil)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "must not be nil")
// 	})

// 	t.Run("different length primes", func(t *testing.T) {
// 		// Create primes with different announced lengths
// 		pBig, _ := rand.Prime(rand.Reader, 32)
// 		qBig, _ := rand.Prime(rand.Reader, 64)

// 		pNat, _ := num.N().FromBytes(pBig.Bytes())
// 		qNat, _ := num.N().FromBytes(qBig.Bytes())

// 		_, err := znstar.NewRSAGroup(pNat, qNat)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "same length")
// 	})

// 	t.Run("non-prime p", func(t *testing.T) {
// 		nonPrime := num.N().FromUint64(15) // 15 = 3*5, not prime
// 		_, err := znstar.NewRSAGroup(nonPrime, q)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "must be prime")
// 	})

// 	t.Run("non-prime q", func(t *testing.T) {
// 		nonPrime := num.N().FromUint64(21) // 21 = 3*7, not prime
// 		_, err := znstar.NewRSAGroup(p, nonPrime)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "must be prime")
// 	})

// 	t.Run("larger primes", func(t *testing.T) {
// 		// Test with cryptographically sized primes
// 		pBig, _ := rand.Prime(rand.Reader, 512)
// 		qBig, _ := rand.Prime(rand.Reader, 512)

// 		pNat, _ := num.N().FromBytes(pBig.Bytes())
// 		qNat, _ := num.N().FromBytes(qBig.Bytes())

// 		rsaGroup, err := znstar.NewRSAGroup(pNat, qNat)
// 		require.NoError(t, err)
// 		assert.NotNil(t, rsaGroup)

// 		// Verify modulus is p*q
// 		expectedN := new(big.Int).Mul(pBig, qBig)
// 		expectedModulus, _ := num.NPlus().FromBytes(expectedN.Bytes())
// 		assert.True(t, expectedModulus.Equal(rsaGroup.Modulus()))
// 	})
// }

// // TestNewPaillierGroup tests creating a Paillier group
// func TestNewPaillierGroup(t *testing.T) {
// 	// Small primes for testing
// 	p := num.N().FromUint64(7)
// 	q := num.N().FromUint64(11)

// 	t.Run("valid primes", func(t *testing.T) {
// 		paillierGroup, err := znstar.NewPaillierGroup(p, q)
// 		require.NoError(t, err)
// 		assert.NotNil(t, paillierGroup)

// 		// Modulus should be (p*q)^2 = 77^2 = 5929
// 		expectedModulus, _ := num.NPlus().FromUint64(5929)
// 		assert.True(t, expectedModulus.Equal(paillierGroup.Modulus()))
// 		assert.Equal(t, cardinal.Unknown(), paillierGroup.Order())
// 	})

// 	t.Run("nil primes", func(t *testing.T) {
// 		_, err := znstar.NewPaillierGroup(nil, q)
// 		assert.Error(t, err)

// 		_, err = znstar.NewPaillierGroup(p, nil)
// 		assert.Error(t, err)
// 	})

// 	t.Run("larger Paillier primes", func(t *testing.T) {
// 		// Test with Paillier-sized primes
// 		pBig, _ := rand.Prime(rand.Reader, 1024)
// 		qBig, _ := rand.Prime(rand.Reader, 1024)

// 		pNat, _ := num.N().FromBytes(pBig.Bytes())
// 		qNat, _ := num.N().FromBytes(qBig.Bytes())

// 		paillierGroup, err := znstar.NewPaillierGroup(pNat, qNat)
// 		require.NoError(t, err)
// 		assert.NotNil(t, paillierGroup)

// 		// Verify modulus is (p*q)^2
// 		n := new(big.Int).Mul(pBig, qBig)
// 		n2 := new(big.Int).Mul(n, n)
// 		expectedModulus, _ := num.NPlus().FromBytes(n2.Bytes())
// 		assert.True(t, expectedModulus.Equal(paillierGroup.Modulus()))
// 	})
// }

// // TestUnitOperations tests basic unit operations
// func TestUnitOperations(t *testing.T) {
// 	// Create a simple group mod 15
// 	m, _ := num.NPlus().FromUint64(15)
// 	type UnknownExp = *struct{}
// 	uzmod, err := znstar.NewUnitGroupOfUnknownOrder[UnknownExp](m)
// 	require.NoError(t, err)

// 	t.Run("One element", func(t *testing.T) {
// 		one := uzmod.One()
// 		assert.NotNil(t, one)
// 		assert.True(t, one.IsOne())
// 		assert.True(t, one.IsOpIdentity())
// 		assert.Equal(t, uzmod, one.Structure())
// 	})

// 	t.Run("FromUint64", func(t *testing.T) {
// 		// 2 is coprime to 15
// 		unit2, err := uzmod.FromUint64(2)
// 		require.NoError(t, err)
// 		assert.NotNil(t, unit2)
// 		assert.False(t, unit2.IsOne())

// 		// 3 is not coprime to 15 (gcd(3,15) = 3)
// 		_, err = uzmod.FromUint64(3)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "not coprime")

// 		// 0 is not coprime to 15
// 		_, err = uzmod.FromUint64(0)
// 		assert.Error(t, err)
// 	})

// 	t.Run("Multiplication", func(t *testing.T) {
// 		unit2, _ := uzmod.FromUint64(2)
// 		unit7, _ := uzmod.FromUint64(7)

// 		// 2 * 7 = 14 mod 15
// 		result := unit2.Mul(unit7)
// 		assert.NotNil(t, result)

// 		// Check commutativity
// 		result2 := unit7.Mul(unit2)
// 		assert.True(t, result.Equal(result2))

// 		// Multiply by one
// 		resultOne := unit2.Mul(uzmod.One())
// 		assert.True(t, unit2.Equal(resultOne))
// 	})

// 	t.Run("Square", func(t *testing.T) {
// 		unit2, _ := uzmod.FromUint64(2)

// 		// 2^2 = 4 mod 15
// 		squared := unit2.Square()
// 		assert.NotNil(t, squared)

// 		// Should be same as Mul(self)
// 		squared2 := unit2.Mul(unit2)
// 		assert.True(t, squared.Equal(squared2))
// 	})

// 	t.Run("Inverse", func(t *testing.T) {
// 		unit2, _ := uzmod.FromUint64(2)

// 		// 2 * 8 = 16 ≡ 1 (mod 15), so 2^{-1} = 8
// 		inv := unit2.Inv()
// 		assert.NotNil(t, inv)

// 		// Verify: 2 * inv = 1
// 		product := unit2.Mul(inv)
// 		assert.True(t, product.IsOne())

// 		// Try with TryInv
// 		inv2, err := unit2.TryInv()
// 		require.NoError(t, err)
// 		assert.True(t, inv.Equal(inv2))
// 	})

// 	t.Run("Division", func(t *testing.T) {
// 		unit2, _ := uzmod.FromUint64(2)
// 		unit7, _ := uzmod.FromUint64(7)

// 		// 7 / 2 = 7 * 2^{-1} = 7 * 8 = 56 ≡ 11 (mod 15)
// 		result := unit7.Div(unit2)
// 		assert.NotNil(t, result)

// 		// Verify: result * 2 = 7
// 		check := result.Mul(unit2)
// 		assert.True(t, check.Equal(unit7))

// 		// Try with TryDiv
// 		result2, err := unit7.TryDiv(unit2)
// 		require.NoError(t, err)
// 		assert.True(t, result.Equal(result2))
// 	})

// 	t.Run("Exponentiation", func(t *testing.T) {
// 		unit2, _ := uzmod.FromUint64(2)

// 		// 2^3 = 8 mod 15
// 		exp3 := num.N().FromUint64(3)
// 		result := unit2.Exp(exp3)
// 		assert.NotNil(t, result)

// 		// Verify by repeated multiplication
// 		expected := unit2.Mul(unit2).Mul(unit2)
// 		assert.True(t, result.Equal(expected))

// 		// 2^0 = 1
// 		exp0 := num.N().FromUint64(0)
// 		result0 := unit2.Exp(exp0)
// 		assert.True(t, result0.IsOne())
// 	})
// }

// // TestRSAGroupOperations tests operations specific to RSA groups
// func TestRSAGroupOperations(t *testing.T) {
// 	// Use small primes for predictable results
// 	p := num.N().FromUint64(11)
// 	q := num.N().FromUint64(13)

// 	rsaGroup, err := znstar.NewRSAGroup(p, q)
// 	require.NoError(t, err)

// 	// N = 11 * 13 = 143
// 	// φ(N) = 10 * 12 = 120

// 	t.Run("Exponentiation with CRT", func(t *testing.T) {
// 		// Test that exponentiation works correctly
// 		base, err := rsaGroup.FromUint64(2)
// 		require.NoError(t, err)

// 		// 2^5 mod 143
// 		exp := num.N().FromUint64(5)
// 		result := base.Exp(exp)

// 		// Manual calculation: 2^5 = 32 mod 143
// 		expected, err := rsaGroup.FromUint64(32)
// 		require.NoError(t, err)
// 		assert.True(t, result.Equal(expected))
// 	})

// 	t.Run("Large exponent", func(t *testing.T) {
// 		base, err := rsaGroup.FromUint64(2)
// 		require.NoError(t, err)

// 		// Test with φ(N) = 120
// 		// By Euler's theorem: 2^120 ≡ 1 (mod 143)
// 		exp := num.N().FromUint64(120)
// 		result := base.Exp(exp)
// 		assert.True(t, result.IsOne())

// 		// Test with φ(N) + 1 = 121
// 		// Should be same as 2^1 = 2
// 		exp121 := num.N().FromUint64(121)
// 		result121 := base.Exp(exp121)
// 		assert.True(t, result121.Equal(base))
// 	})
// }

// // TestPaillierGroupOperations tests operations specific to Paillier groups
// func TestPaillierGroupOperations(t *testing.T) {
// 	// Use small primes for testing
// 	p := num.N().FromUint64(7)
// 	q := num.N().FromUint64(11)

// 	paillierGroup, err := znstar.NewPaillierGroup(p, q)
// 	require.NoError(t, err)

// 	// N = 7 * 11 = 77
// 	// N^2 = 5929

// 	t.Run("Elements in Z*_{N^2}", func(t *testing.T) {
// 		// Test valid elements
// 		unit2, err := paillierGroup.FromUint64(2)
// 		require.NoError(t, err)
// 		assert.NotNil(t, unit2)

// 		// Test element not coprime to N^2
// 		// 77 divides N^2, so it's not coprime
// 		_, err = paillierGroup.FromUint64(77)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "not coprime")
// 	})

// 	t.Run("Multiplication in Paillier group", func(t *testing.T) {
// 		unit2, _ := paillierGroup.FromUint64(2)
// 		unit3, _ := paillierGroup.FromUint64(3)

// 		// 2 * 3 = 6 mod N^2
// 		result := unit2.Mul(unit3)
// 		expected, _ := paillierGroup.FromUint64(6)
// 		assert.True(t, result.Equal(expected))
// 	})
// }

// // TestFromBytes tests creating units from byte arrays
// func TestFromBytes(t *testing.T) {
// 	m, _ := num.NPlus().FromUint64(15)
// 	type UnknownExp = *struct{}
// 	uzmod, err := znstar.NewUnitGroupOfUnknownOrder[UnknownExp](m)
// 	require.NoError(t, err)

// 	t.Run("valid bytes", func(t *testing.T) {
// 		// 2 is coprime to 15
// 		bytes := big.NewInt(2).Bytes()
// 		unit, err := uzmod.FromBytes(bytes)
// 		require.NoError(t, err)
// 		assert.NotNil(t, unit)

// 		// Verify it's the same as FromUint64(2)
// 		unit2, _ := uzmod.FromUint64(2)
// 		assert.True(t, unit.Equal(unit2))
// 	})

// 	t.Run("empty bytes", func(t *testing.T) {
// 		_, err := uzmod.FromBytes([]byte{})
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "empty")
// 	})

// 	t.Run("non-coprime bytes", func(t *testing.T) {
// 		// 3 is not coprime to 15
// 		bytes := big.NewInt(3).Bytes()
// 		_, err := uzmod.FromBytes(bytes)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "not coprime")
// 	})
// }

// // TestFromCardinal tests creating units from cardinals
// func TestFromCardinal(t *testing.T) {
// 	m, _ := num.NPlus().FromUint64(15)
// 	type UnknownExp = *struct{}
// 	uzmod, err := znstar.NewUnitGroupOfUnknownOrder[UnknownExp](m)
// 	require.NoError(t, err)

// 	t.Run("valid cardinal", func(t *testing.T) {
// 		card := cardinal.New(2)
// 		unit, err := uzmod.FromCardinal(card)
// 		require.NoError(t, err)
// 		assert.NotNil(t, unit)

// 		// Verify cardinal - check value equality
// 		assert.Equal(t, card.Uint64(), unit.Cardinal().Uint64())
// 	})

// 	t.Run("non-coprime cardinal", func(t *testing.T) {
// 		card := cardinal.New(3) // 3 is not coprime to 15
// 		_, err := uzmod.FromCardinal(card)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "not coprime")
// 	})

// 	t.Run("unknown cardinal", func(t *testing.T) {
// 		card := cardinal.Unknown()
// 		_, err := uzmod.FromCardinal(card)
// 		assert.Error(t, err)
// 	})
// }

// // TestUnitProperties tests various properties of units
// func TestUnitProperties(t *testing.T) {
// 	m, _ := num.NPlus().FromUint64(15)
// 	type UnknownExp = *struct{}
// 	uzmod, err := znstar.NewUnitGroupOfUnknownOrder[UnknownExp](m)
// 	require.NoError(t, err)

// 	unit2, _ := uzmod.FromUint64(2)
// 	unit7, _ := uzmod.FromUint64(7)

// 	t.Run("Clone", func(t *testing.T) {
// 		cloned := unit2.Clone()
// 		assert.True(t, cloned.Equal(unit2))
// 		assert.NotSame(t, cloned, unit2) // Different objects
// 	})

// 	t.Run("String representation", func(t *testing.T) {
// 		str := unit2.String()
// 		assert.NotEmpty(t, str)
// 	})

// 	t.Run("Bytes representation", func(t *testing.T) {
// 		bytes := unit2.Bytes()
// 		assert.NotEmpty(t, bytes)

// 		// Should be able to recreate from bytes
// 		recreated, err := uzmod.FromBytes(bytes)
// 		require.NoError(t, err)
// 		assert.True(t, recreated.Equal(unit2))
// 	})

// 	t.Run("EqualModulus", func(t *testing.T) {
// 		assert.True(t, unit2.EqualModulus(unit7))

// 		// Create another group with different modulus
// 		m2, _ := num.NPlus().FromUint64(35)
// 		uzmod2, _ := znstar.NewUnitGroupOfUnknownOrder[UnknownExp](m2)
// 		unit2_mod35, _ := uzmod2.FromUint64(2)

// 		assert.False(t, unit2.EqualModulus(unit2_mod35))
// 	})

// 	t.Run("IsUnknownOrder", func(t *testing.T) {
// 		assert.True(t, unit2.IsUnknownOrder())
// 	})

// 	t.Run("HashCode", func(t *testing.T) {
// 		hash1 := unit2.HashCode()
// 		hash2 := unit2.Clone().HashCode()
// 		assert.Equal(t, hash1, hash2)

// 		hash3 := unit7.HashCode()
// 		assert.NotEqual(t, hash1, hash3)
// 	})
// }

// // TestEdgeCases tests edge cases and error conditions
// func TestEdgeCases(t *testing.T) {
// 	t.Run("ExpI with positive and negative exponents", func(t *testing.T) {
// 		m, _ := num.NPlus().FromUint64(15)
// 		type UnknownExp = *struct{}
// 		uzmod, _ := znstar.NewUnitGroupOfUnknownOrder[UnknownExp](m)
// 		unit2, _ := uzmod.FromUint64(2)

// 		// Test positive exponent
// 		exp3 := num.Z().FromInt64(3)
// 		result := unit2.ExpI(exp3)
// 		assert.NotNil(t, result)
// 		// 2^3 = 8 mod 15
// 		expected, _ := uzmod.FromUint64(8)
// 		assert.True(t, result.Equal(expected))

// 		// Test negative exponent
// 		expNeg1 := num.Z().FromInt64(-1)
// 		resultNeg := unit2.ExpI(expNeg1)
// 		assert.NotNil(t, resultNeg)
// 		// 2^(-1) = 8 mod 15 (since 2*8 = 16 ≡ 1 mod 15)
// 		expectedInv, _ := uzmod.FromUint64(8)
// 		assert.True(t, resultNeg.Equal(expectedInv))
// 	})

// 	t.Run("nil checks", func(t *testing.T) {
// 		m, _ := num.NPlus().FromUint64(15)
// 		type UnknownExp = *struct{}
// 		uzmod, _ := znstar.NewUnitGroupOfUnknownOrder[UnknownExp](m)
// 		unit2, _ := uzmod.FromUint64(2)

// 		// Exp with nil should panic
// 		assert.Panics(t, func() {
// 			unit2.Exp(nil)
// 		})

// 		// ExpI with nil should panic
// 		assert.Panics(t, func() {
// 			unit2.ExpI(nil)
// 		})
// 	})
// }

// // BenchmarkUnitOperations benchmarks common unit operations
// func BenchmarkUnitOperations(b *testing.B) {
// 	// Create RSA group with 1024-bit primes
// 	pBig, _ := rand.Prime(rand.Reader, 1024)
// 	qBig, _ := rand.Prime(rand.Reader, 1024)

// 	p, _ := num.N().FromBytes(pBig.Bytes())
// 	q, _ := num.N().FromBytes(qBig.Bytes())

// 	rsaGroup, err := znstar.NewRSAGroup(p, q)
// 	require.NoError(b, err)

// 	// Create some test elements
// 	base, _ := rsaGroup.FromUint64(2)
// 	other, _ := rsaGroup.FromUint64(3)
// 	exp := num.N().FromUint64(65537) // Common RSA exponent

// 	b.Run("Multiplication", func(b *testing.B) {
// 		for i := 0; i < b.N; i++ {
// 			_ = base.Mul(other)
// 		}
// 	})

// 	b.Run("Square", func(b *testing.B) {
// 		for i := 0; i < b.N; i++ {
// 			_ = base.Square()
// 		}
// 	})

// 	b.Run("Inverse", func(b *testing.B) {
// 		for i := 0; i < b.N; i++ {
// 			_ = base.Inv()
// 		}
// 	})

// 	b.Run("Exponentiation", func(b *testing.B) {
// 		for i := 0; i < b.N; i++ {
// 			_ = base.Exp(exp)
// 		}
// 	})

// 	b.Run("Division", func(b *testing.B) {
// 		for i := 0; i < b.N; i++ {
// 			_ = base.Div(other)
// 		}
// 	})
// }

// // BenchmarkGroupCreation benchmarks creating different types of groups
// func BenchmarkGroupCreation(b *testing.B) {
// 	b.Run("RSAGroup-1024", func(b *testing.B) {
// 		pBig, _ := rand.Prime(rand.Reader, 1024)
// 		qBig, _ := rand.Prime(rand.Reader, 1024)
// 		p, _ := num.N().FromBytes(pBig.Bytes())
// 		q, _ := num.N().FromBytes(qBig.Bytes())

// 		b.ResetTimer()
// 		for i := 0; i < b.N; i++ {
// 			_, _ = znstar.NewRSAGroup(p, q)
// 		}
// 	})

// 	b.Run("PaillierGroup-1024", func(b *testing.B) {
// 		pBig, _ := rand.Prime(rand.Reader, 1024)
// 		qBig, _ := rand.Prime(rand.Reader, 1024)
// 		p, _ := num.N().FromBytes(pBig.Bytes())
// 		q, _ := num.N().FromBytes(qBig.Bytes())

// 		b.ResetTimer()
// 		for i := 0; i < b.N; i++ {
// 			_, _ = znstar.NewPaillierGroup(p, q)
// 		}
// 	})

// 	b.Run("UnknownOrderGroup", func(b *testing.B) {
// 		nBig := big.NewInt(1)
// 		nBig.Lsh(nBig, 2048) // 2^2048
// 		nBig.Sub(nBig, big.NewInt(1)) // 2^2048 - 1

// 		m, _ := num.NPlus().FromBytes(nBig.Bytes())

// 		b.ResetTimer()
// 		type UnknownExp = *struct{}
// 		for i := 0; i < b.N; i++ {
// 			_, _ = znstar.NewUnitGroupOfUnknownOrder[UnknownExp](m)
// 		}
// 	})
// }
