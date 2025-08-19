package impl_test

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl"
	"github.com/cronokirby/saferith"
)

// NOTE: newNat is already defined in nat_test.go

func newNatFromBig(b *big.Int) *impl.Nat {
	return (*impl.Nat)(new(saferith.Nat).SetBig(b, b.BitLen()))
}

func newModulusOddPrime(p *big.Int) *impl.ModulusOddPrime {
	pNat := (*impl.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))
	m, ok := impl.NewModulusOddPrime(pNat)
	if ok != ct.True {
		panic("failed to create ModulusOddPrime")
	}
	return m
}

func TestNewModulusFromNat(t *testing.T) {
	t.Parallel()

	t.Run("odd prime", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(7))
		m, err := impl.NewModulusFromNat(p)
		assert.NoError(t, err)

		// Should return ModulusOddPrime type
		_, ok := m.(*impl.ModulusOddPrime)
		assert.True(t, ok, "Expected ModulusOddPrime for prime 7")
	})

	t.Run("not odd prime", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(15)) // 3*5, not prime
		m, err := impl.NewModulusFromNat(p)
		assert.NoError(t, err)

		// Should return ModulusOdd type (odd composite)
		_, ok := m.(*impl.ModulusOdd)
		assert.True(t, ok, "Expected ModulusOdd for 15 (odd composite)")
	})

	t.Run("even number", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(10))
		m, err := impl.NewModulusFromNat(p)
		assert.NoError(t, err)

		// Should return generic Modulus type (not ModulusOdd or ModulusOddPrime)
		_, ok := m.(*impl.Modulus)
		assert.True(t, ok, "Expected Modulus for even number 10")
	})
}

func TestModulusOddPrime_BasicOperations(t *testing.T) {
	t.Parallel()

	m := newModulusOddPrime(big.NewInt(7))

	t.Run("Mod", func(t *testing.T) {
		tests := []struct {
			name string
			x    int64
			want int64
		}{
			{"small positive", 3, 3},
			{"equals modulus", 7, 0},
			{"greater than modulus", 10, 3},
			{"multiple of modulus", 14, 0},
			{"large value", 100, 2},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				x := newNatFromBig(big.NewInt(tt.x))
				out := newNatFromBig(big.NewInt(0))

				m.Mod(out, x)
				assert.Equal(t, uint64(tt.want), out.Uint64())
			})
		}
	})

	t.Run("Add", func(t *testing.T) {
		tests := []struct {
			name string
			x, y int64
			want int64
		}{
			{"simple add", 2, 3, 5},
			{"add with wrap", 5, 4, 2}, // 9 mod 7 = 2
			{"add to zero", 0, 6, 6},
			{"add zeros", 0, 0, 0},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				x := newNatFromBig(big.NewInt(tt.x))
				y := newNatFromBig(big.NewInt(tt.y))
				out := newNatFromBig(big.NewInt(0))

				m.ModAdd(out, x, y)
				assert.Equal(t, uint64(tt.want), out.Uint64())
			})
		}
	})

	t.Run("Sub", func(t *testing.T) {
		tests := []struct {
			name string
			x, y int64
			want int64
		}{
			{"simple sub", 5, 2, 3},
			{"sub with wrap", 2, 5, 4}, // 2-5 = -3 ≡ 4 mod 7
			{"sub from zero", 0, 3, 4}, // 0-3 = -3 ≡ 4 mod 7
			{"sub zeros", 0, 0, 0},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				x := newNatFromBig(big.NewInt(tt.x))
				y := newNatFromBig(big.NewInt(tt.y))
				out := newNatFromBig(big.NewInt(0))

				m.ModSub(out, x, y)
				assert.Equal(t, uint64(tt.want), out.Uint64())
			})
		}
	})

	t.Run("Mul", func(t *testing.T) {
		tests := []struct {
			name string
			x, y int64
			want int64
		}{
			{"simple mul", 2, 3, 6},
			{"mul with wrap", 3, 4, 5}, // 12 mod 7 = 5
			{"mul by zero", 5, 0, 0},
			{"mul by one", 5, 1, 5},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				x := newNatFromBig(big.NewInt(tt.x))
				y := newNatFromBig(big.NewInt(tt.y))
				out := newNatFromBig(big.NewInt(0))

				m.ModMul(out, x, y)
				assert.Equal(t, uint64(tt.want), out.Uint64())
			})
		}
	})

	t.Run("Neg", func(t *testing.T) {
		tests := []struct {
			name string
			x    int64
			want int64
		}{
			{"neg positive", 3, 4},  // -3 ≡ 4 mod 7
			{"neg zero", 0, 0},      // -0 = 0
			{"neg one", 1, 6},       // -1 ≡ 6 mod 7
			{"neg modulus-1", 6, 1}, // -6 ≡ 1 mod 7
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				x := newNatFromBig(big.NewInt(tt.x))
				out := newNatFromBig(big.NewInt(0))

				m.ModNeg(out, x)
				assert.Equal(t, uint64(tt.want), out.Uint64())
			})
		}
	})
}

func TestModulusOddPrime_Inv(t *testing.T) {
	t.Parallel()

	m := newModulusOddPrime(big.NewInt(7))

	tests := []struct {
		name string
		x    int64
		want int64
	}{
		{"inv of 1", 1, 1}, // 1 * 1 = 1 mod 7
		{"inv of 2", 2, 4}, // 2 * 4 = 8 ≡ 1 mod 7
		{"inv of 3", 3, 5}, // 3 * 5 = 15 ≡ 1 mod 7
		{"inv of 4", 4, 2}, // 4 * 2 = 8 ≡ 1 mod 7
		{"inv of 5", 5, 3}, // 5 * 3 = 15 ≡ 1 mod 7
		{"inv of 6", 6, 6}, // 6 * 6 = 36 ≡ 1 mod 7
		{"inv of 0", 0, 0}, // Special case, but saferith returns ok=true for odd moduli
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			x := newNatFromBig(big.NewInt(tt.x))
			out := newNatFromBig(big.NewInt(0))

			ok := m.ModInv(out, x)
			if tt.x == 0 {
				// 0 has no modular inverse
				assert.Equal(t, ct.False, ok)
			} else {
				assert.Equal(t, ct.True, ok)
				assert.Equal(t, uint64(tt.want), out.Uint64())

				// Verify that x * inv(x) ≡ 1 mod 7
				product := newNatFromBig(big.NewInt(0))
				m.ModMul(product, x, out)
				assert.Equal(t, uint64(1), product.Uint64(), "x * inv(x) should be 1 mod p")
			}
		})
	}
}

func TestModulusOddPrime_Sqrt(t *testing.T) {
	t.Parallel()

	m := newModulusOddPrime(big.NewInt(7))

	tests := []struct {
		name     string
		x        int64
		wantRoot int64
		wantOk   ct.Bool
	}{
		{"sqrt of 0", 0, 0, ct.True},
		{"sqrt of 1", 1, 1, ct.True},     // 1^2 = 1
		{"sqrt of 2", 2, 3, ct.True},     // 3^2 = 9 ≡ 2 mod 7 or 4^2 = 16 ≡ 2 mod 7
		{"sqrt of 4", 4, 2, ct.True},     // 2^2 = 4
		{"no sqrt of 3", 3, 0, ct.False}, // 3 is not a quadratic residue mod 7
		{"no sqrt of 5", 5, 0, ct.False}, // 5 is not a quadratic residue mod 7
		{"no sqrt of 6", 6, 0, ct.False}, // 6 is not a quadratic residue mod 7
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			x := newNatFromBig(big.NewInt(tt.x))
			out := newNatFromBig(big.NewInt(0))

			ok := m.ModSqrt(out, x)
			assert.Equal(t, tt.wantOk, ok)

			if ok == ct.True {
				// Verify that out^2 ≡ x mod 7
				squared := newNatFromBig(big.NewInt(0))
				m.ModMul(squared, out, out)
				assert.Equal(t, uint64(tt.x), squared.Uint64(), "sqrt(x)^2 should equal x mod p")

				// The actual root might be different from expected (e.g., 3 or 4 for sqrt(2))
				// So we just verify the property, not the exact value
			}
		})
	}
}

func TestModulusOddPrime_Div(t *testing.T) {
	t.Parallel()

	m := newModulusOddPrime(big.NewInt(7))

	tests := []struct {
		name string
		x, y int64
		want int64
	}{
		{"div by 1", 6, 1, 6},    // 6/1 = 6
		{"div by self", 5, 5, 1}, // 5/5 = 1
		{"6 div by 2", 6, 2, 3},  // 6/2 = 3
		{"1 div by 2", 1, 2, 4},  // 1/2 ≡ 1 * 4 = 4 mod 7 (since 2^-1 = 4)
		{"3 div by 3", 3, 3, 1},  // 3/3 = 1
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			x := newNatFromBig(big.NewInt(tt.x))
			y := newNatFromBig(big.NewInt(tt.y))
			out := newNatFromBig(big.NewInt(0))

			m.ModDiv(out, x, y)
			assert.Equal(t, uint64(tt.want), out.Uint64())

			// Verify that out * y ≡ x mod 7
			product := newNatFromBig(big.NewInt(0))
			m.ModMul(product, out, y)
			assert.Equal(t, uint64(tt.x), product.Uint64(), "div(x,y) * y should equal x mod p")
		})
	}
}

func TestModulusOddPrime_Properties(t *testing.T) {
	t.Parallel()

	p := big.NewInt(97)
	m := newModulusOddPrime(p)

	t.Run("BitLen", func(t *testing.T) {
		// 97 in binary is 1100001, which is 7 bits
		assert.Equal(t, uint(7), m.BitLen())
	})

	t.Run("Nat", func(t *testing.T) {
		n := m.Nat()
		assert.Equal(t, uint64(97), n.Uint64())
	})

	t.Run("Bytes", func(t *testing.T) {
		bytes := m.Bytes()
		expected := p.Bytes()
		assert.Equal(t, expected, bytes)
	})

	t.Run("String", func(t *testing.T) {
		str := m.String()
		assert.Contains(t, str, "61") // 97 in hex is 0x61
	})

	t.Run("InRange", func(t *testing.T) {
		tests := []struct {
			name string
			x    int64
			want ct.Bool
		}{
			{"zero", 0, ct.True},
			{"small positive", 50, ct.True},
			{"p-1", 96, ct.True},
			{"equals p", 97, ct.False},
			{"greater than p", 100, ct.False},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				x := newNatFromBig(big.NewInt(tt.x))
				got := m.InRange(x)
				assert.Equal(t, tt.want, got)
			})
		}
	})

	t.Run("IsUnit", func(t *testing.T) {
		tests := []struct {
			name string
			x    int64
			want ct.Bool
		}{
			{"1 is unit", 1, ct.True},
			{"2 is unit", 2, ct.True},
			{"96 is unit", 96, ct.True},
			{"0 is not unit", 0, ct.False},
			{"97 (p) is not unit", 97, ct.False}, // gcd(97, 97) = 97 ≠ 1
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				x := newNatFromBig(big.NewInt(tt.x))
				got := m.IsUnit(x)
				assert.Equal(t, tt.want, got)
			})
		}
	})
}

func TestModulusOddPrime_Exp(t *testing.T) {
	t.Parallel()

	m := newModulusOddPrime(big.NewInt(7))

	tests := []struct {
		name string
		base int64
		exp  int64
		want int64
	}{
		{"2^0", 2, 0, 1},
		{"2^1", 2, 1, 2},
		{"2^2", 2, 2, 4},
		{"2^3", 2, 3, 1}, // 8 mod 7 = 1
		{"3^2", 3, 2, 2}, // 9 mod 7 = 2
		{"3^3", 3, 3, 6}, // 27 mod 7 = 6
		{"5^2", 5, 2, 4}, // 25 mod 7 = 4
		{"0^5", 0, 5, 0},
		{"1^100", 1, 100, 1},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			base := newNatFromBig(big.NewInt(tt.base))
			exp := newNatFromBig(big.NewInt(tt.exp))
			out := newNatFromBig(big.NewInt(0))

			m.ModExp(out, base, exp)
			assert.Equal(t, uint64(tt.want), out.Uint64())
		})
	}
}

func TestModulus_Sqrt(t *testing.T) {
	t.Parallel()

	// Test with even number 10 - use Modulus constructor directly
	p := newNatFromBig(big.NewInt(10))
	m, ok := impl.NewModulus(p)
	assert.Equal(t, ct.True, ok, "Should be able to create Modulus for even number")

	tests := []struct {
		name     string
		x        int64
		wantRoot int64
		wantOk   ct.Bool
	}{
		{"sqrt of 0", 0, 0, ct.True},
		{"sqrt of 1", 1, 1, ct.True},
		{"sqrt of 4", 4, 2, ct.True},
		{"sqrt of 9", 9, 3, ct.True},
		{"no sqrt of 2", 2, 0, ct.False},
		{"no sqrt of 3", 3, 0, ct.False},
		{"no sqrt of 5", 5, 0, ct.False},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			x := newNatFromBig(big.NewInt(tt.x))
			out := newNatFromBig(big.NewInt(0))

			ok := m.ModSqrt(out, x)
			assert.Equal(t, tt.wantOk, ok)

			if ok == ct.True {
				assert.Equal(t, uint64(tt.wantRoot), out.Uint64())

				// Verify that out^2 ≡ x mod 15
				squared := newNatFromBig(big.NewInt(0))
				m.ModMul(squared, out, out)
				xMod := newNatFromBig(big.NewInt(0))
				m.Mod(xMod, x)
				assert.Equal(t, xMod.Uint64(), squared.Uint64(), "sqrt(x)^2 should equal x mod p")
			}
		})
	}
}

func TestModulusInterfaces(t *testing.T) {
	t.Parallel()

	// These interface checks are now done at compile time in modulus_cgo.go
	// Just verify we can create instances
	t.Run("Can create ModulusOddPrime", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(7))
		m, ok := impl.NewModulusOddPrime(p)
		assert.Equal(t, ct.True, ok)
		assert.NotNil(t, m)
	})

	t.Run("Can create ModulusOdd", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(15)) // odd composite
		m, ok := impl.NewModulusOdd(p)
		assert.Equal(t, ct.True, ok)
		assert.NotNil(t, m)
	})

	t.Run("Can create Modulus", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(10)) // even
		m, ok := impl.NewModulus(p)
		assert.Equal(t, ct.True, ok)
		assert.NotNil(t, m)
	})
}

// TestModulusCachingPerformance tests Montgomery context caching benefits
func TestModulusCachingPerformance(t *testing.T) {
	testCases := []struct {
		name      string
		primeBits int
		ops       int
	}{
		{"512-bit prime, 100 ops", 512, 100},
		{"1024-bit prime, 100 ops", 1024, 100},
		{"2048-bit prime, 50 ops", 2048, 50},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a prime
			pBig, _ := rand.Prime(rand.Reader, tc.primeBits)
			p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, tc.primeBits).Resize(tc.primeBits))
			
			// Create ModulusOddPrime with cached Montgomery context
			pMod, ok := impl.NewModulusOddPrime(p)
			require.Equal(t, ct.True, ok)

			// Generate test data
			bases := make([]*impl.Nat, tc.ops)
			exps := make([]*impl.Nat, tc.ops)
			for i := 0; i < tc.ops; i++ {
				base, _ := rand.Int(rand.Reader, pBig)
				bases[i] = (*impl.Nat)(new(saferith.Nat).SetBig(base, tc.primeBits).Resize(tc.primeBits))
				
				exp, _ := rand.Int(rand.Reader, pBig)
				exps[i] = (*impl.Nat)(new(saferith.Nat).SetBig(exp, tc.primeBits).Resize(tc.primeBits))
			}
			
			result := (*impl.Nat)(new(saferith.Nat))

			// Test ModExp with reusing modulus (cached Montgomery context)
			start := time.Now()
			for i := 0; i < tc.ops; i++ {
				pMod.ModExp(result, bases[i], exps[i])
			}
			reuseTime := time.Since(start)

			// Test with recreating the modulus each time (no cache benefit)
			start = time.Now()
			for i := 0; i < tc.ops; i++ {
				newPMod, _ := impl.NewModulusOddPrime(p)
				newPMod.ModExp(result, bases[i], exps[i])
			}
			recreateTime := time.Since(start)

			speedup := float64(recreateTime) / float64(reuseTime)

			t.Logf("ModExp caching results for %s:", tc.name)
			t.Logf("  Reusing modulus (cached):    %v", reuseTime)
			t.Logf("  Recreating modulus each time: %v", recreateTime)
			t.Logf("  Speedup from caching: %.2fx", speedup)
		})
	}
}

func BenchmarkModulusOperations(b *testing.B) {
	p := big.NewInt(997) // Large prime
	m := newModulusOddPrime(p)

	x := newNatFromBig(big.NewInt(123))
	y := newNatFromBig(big.NewInt(456))
	out := newNatFromBig(big.NewInt(0))

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.ModAdd(out, x, y)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.ModMul(out, x, y)
		}
	})

	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.ModInv(out, x)
		}
	})

	b.Run("Sqrt", func(b *testing.B) {
		// Use a quadratic residue
		qr := newNatFromBig(big.NewInt(4))
		for i := 0; i < b.N; i++ {
			m.ModSqrt(out, qr)
		}
	})

	b.Run("Exp", func(b *testing.B) {
		exp := newNatFromBig(big.NewInt(100))
		for i := 0; i < b.N; i++ {
			m.ModExp(out, x, exp)
		}
	})
}
