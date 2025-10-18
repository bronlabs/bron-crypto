package numct_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/cronokirby/saferith"
)

func newNatFromBig(b *big.Int) *numct.Nat {
	return (*numct.Nat)(new(saferith.Nat).SetBig(b, b.BitLen()))
}

func newModulusOddPrime(p *big.Int) *numct.ModulusOddPrime {
	pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))
	m, ok := numct.NewModulusOddPrime(pNat)
	if ok != ct.True {
		panic("failed to create ModulusOddPrime")
	}
	return m
}

func TestNewModulusFromNat(t *testing.T) {
	t.Parallel()

	t.Run("odd prime", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(7))
		m, ok := numct.NewModulus(p)
		assert.Equal(t, ct.True, ok, "Failed to create modulus")

		// Should return ModulusOddPrime type
		_, isOddPrime := m.(*numct.ModulusOddPrime)
		assert.True(t, isOddPrime, "Expected ModulusOddPrime for prime 7")
	})

	t.Run("not odd prime", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(15)) // 3*5, not prime
		m, ok := numct.NewModulus(p)
		assert.Equal(t, ct.True, ok, "Failed to create modulus")

		// Should return ModulusOdd type (odd composite)
		_, isOdd := m.(*numct.ModulusOdd)
		assert.True(t, isOdd, "Expected ModulusOdd for 15 (odd composite)")
	})

	t.Run("even number", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(10))
		m, ok := numct.NewModulus(p)
		assert.Equal(t, ct.True, ok, "Failed to create modulus")

		// Should return generic Modulus type (not ModulusOdd or ModulusOddPrime)
		_, isNonZero := m.(*numct.ModulusNonZero)
		assert.True(t, isNonZero, "Expected Modulus for even number 10")
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
				got := m.IsInRange(x)
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
	m, ok := numct.NewModulusNonZero(p)
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
		m, ok := numct.NewModulusOddPrime(p)
		assert.Equal(t, ct.True, ok)
		assert.NotNil(t, m)
	})

	t.Run("Can create ModulusOdd", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(15)) // odd composite
		m, ok := numct.NewModulusOdd(p)
		assert.Equal(t, ct.True, ok)
		assert.NotNil(t, m)
	})

	t.Run("Can create Modulus", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(10)) // even
		m, ok := numct.NewModulusNonZero(p)
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
			p := (*numct.Nat)(new(saferith.Nat).SetBig(pBig, tc.primeBits).Resize(tc.primeBits))

			// Create ModulusOddPrime with cached Montgomery context
			pMod, ok := numct.NewModulusOddPrime(p)
			require.Equal(t, ct.True, ok)

			// Generate test data
			bases := make([]*numct.Nat, tc.ops)
			exps := make([]*numct.Nat, tc.ops)
			for i := 0; i < tc.ops; i++ {
				base, _ := rand.Int(rand.Reader, pBig)
				bases[i] = (*numct.Nat)(new(saferith.Nat).SetBig(base, tc.primeBits).Resize(tc.primeBits))

				exp, _ := rand.Int(rand.Reader, pBig)
				exps[i] = (*numct.Nat)(new(saferith.Nat).SetBig(exp, tc.primeBits).Resize(tc.primeBits))
			}

			result := (*numct.Nat)(new(saferith.Nat))

			// Test ModExp with reusing modulus (cached Montgomery context)
			start := time.Now()
			for i := 0; i < tc.ops; i++ {
				pMod.ModExp(result, bases[i], exps[i])
			}
			reuseTime := time.Since(start)

			// Test with recreating the modulus each time (no cache benefit)
			start = time.Now()
			for i := 0; i < tc.ops; i++ {
				newPMod, _ := numct.NewModulusOddPrime(p)
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

func TestModSymmetric(t *testing.T) {
	t.Parallel()

	// Test with prime modulus 11
	p := big.NewInt(11)
	m := newModulusOddPrime(p)

	testCases := []struct {
		name     string
		input    int64
		expected int64 // Expected value in symmetric range [-5, 5]
	}{
		{"Zero", 0, 0},
		{"Small positive", 3, 3},
		{"Small negative equivalent", 8, -3}, // 8 ≡ -3 (mod 11)
		{"At boundary positive", 5, 5},
		{"At boundary negative", 6, -5}, // 6 ≡ -5 (mod 11)
		{"Large positive", 25, 3},       // 25 ≡ 3 (mod 11)
		{"Modulus minus 1", 10, -1},     // 10 ≡ -1 (mod 11)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := newNatFromBig(big.NewInt(tc.input))
			var output numct.Int
			m.ModSymmetric(&output, input)

			// Convert output to big.Int for comparison
			outputBig := new(big.Int)
			if output.IsNegative() == ct.True {
				// Get the absolute value
				var abs numct.Int
				abs.Neg(&output) // abs = -output (which makes it positive)
				outputBig.SetBytes(abs.Bytes())
				outputBig.Neg(outputBig) // Make it negative again
			} else {
				outputBig.SetBytes(output.Bytes())
			}

			assert.Equal(t, tc.expected, outputBig.Int64(),
				"ModSymmetric(%d) = %d, expected %d", tc.input, outputBig.Int64(), tc.expected)
		})
	}
}

func TestModInv_Comprehensive(t *testing.T) {
	t.Parallel()

	t.Run("Prime modulus", func(t *testing.T) {
		// Test with prime modulus 13
		p := big.NewInt(13)
		m := newModulusOddPrime(p)

		testCases := []struct {
			name        string
			input       int64
			hasInverse  bool
			expectedInv int64
		}{
			{"Zero has no inverse", 0, false, 0},
			{"One is self-inverse", 1, true, 1},
			{"Two", 2, true, 7},          // 2 * 7 = 14 ≡ 1 (mod 13)
			{"Three", 3, true, 9},        // 3 * 9 = 27 ≡ 1 (mod 13)
			{"Four", 4, true, 10},        // 4 * 10 = 40 ≡ 1 (mod 13)
			{"Twelve", 12, true, 12},     // 12 * 12 = 144 ≡ 1 (mod 13)
			{"Large value", 27, true, 1}, // 27 ≡ 1 (mod 13), so inv is 1
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				a := newNatFromBig(big.NewInt(tc.input))
				var inv numct.Nat
				ok := m.ModInv(&inv, a)

				if tc.hasInverse {
					assert.Equal(t, ct.True, ok, "Expected inverse to exist")

					// Verify a * inv ≡ 1 (mod p)
					var product numct.Nat
					m.ModMul(&product, a, &inv)
					one := newNatFromBig(big.NewInt(1))
					assert.Equal(t, ct.True, product.Equal(one),
						"Expected %d * inv ≡ 1 (mod %d)", tc.input, p)

					// Check specific expected value if provided
					if tc.expectedInv != 0 {
						invBig := new(big.Int).SetBytes(inv.Bytes())
						invBig.Mod(invBig, p)
						assert.Equal(t, tc.expectedInv, invBig.Int64(),
							"Expected inv(%d) = %d (mod %d)", tc.input, tc.expectedInv, p)
					}
				} else {
					assert.Equal(t, ct.False, ok, "Expected no inverse for %d", tc.input)
				}
			})
		}
	})

	t.Run("Composite odd modulus", func(t *testing.T) {
		// Test with composite modulus 15 = 3 * 5
		n := big.NewInt(15)
		m, ok := numct.NewModulus(newNatFromBig(n))
		require.Equal(t, ct.True, ok, "Failed to create modulus")

		testCases := []struct {
			name       string
			input      int64
			hasInverse bool
		}{
			{"Zero has no inverse", 0, false},
			{"One is self-inverse", 1, true},
			{"Two", 2, true},             // gcd(2, 15) = 1
			{"Three (factor)", 3, false}, // gcd(3, 15) = 3
			{"Four", 4, true},            // gcd(4, 15) = 1
			{"Five (factor)", 5, false},  // gcd(5, 15) = 5
			{"Six", 6, false},            // gcd(6, 15) = 3
			{"Seven", 7, true},           // gcd(7, 15) = 1
			{"Eight", 8, true},           // gcd(8, 15) = 1
			{"Nine", 9, false},           // gcd(9, 15) = 3
			{"Ten", 10, false},           // gcd(10, 15) = 5
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				a := newNatFromBig(big.NewInt(tc.input))
				var inv numct.Nat
				ok := m.ModInv(&inv, a)

				if tc.hasInverse {
					assert.Equal(t, ct.True, ok, "Expected inverse to exist for %d", tc.input)

					// Verify a * inv ≡ 1 (mod n)
					var product numct.Nat
					m.ModMul(&product, a, &inv)
					one := newNatFromBig(big.NewInt(1))
					assert.Equal(t, ct.True, product.Equal(one),
						"Expected %d * inv ≡ 1 (mod %d)", tc.input, n)
				} else {
					assert.Equal(t, ct.False, ok, "Expected no inverse for %d", tc.input)
				}
			})
		}
	})
}

// Benchmark different ModInv implementations
func BenchmarkModInv_Comparison(b *testing.B) {
	// Generate a large prime for testing
	p, _ := rand.Prime(rand.Reader, 2048)

	// Create different modulus types
	pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))

	// ModulusOddPrime (uses Fermat's Little Theorem via ModExp)
	mPrime, ok := numct.NewModulusOddPrime(pNat)
	if ok != ct.True {
		b.Fatal("Failed to create ModulusOddPrime")
	}

	// ModulusOddPrimeBasic (uses saferith.ModInverse)
	mBasic := (*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(pNat)))

	// Test value (make sure it's coprime to p)
	testVal := big.NewInt(12345)
	x := newNatFromBig(testVal)
	var out numct.Nat

	b.Run("ModulusOddPrime_FermatLittleTheorem", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mPrime.ModInv(&out, x)
		}
	})

	b.Run("ModulusOddPrimeBasic_Saferith", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mBasic.ModInv(&out, x)
		}
	})

	// Test with composite odd modulus
	// Use a large RSA-like composite: product of two large primes
	p1, _ := rand.Prime(rand.Reader, 1024)
	p2, _ := rand.Prime(rand.Reader, 1024)
	composite := new(big.Int).Mul(p1, p2)
	compositeNat := (*numct.Nat)(new(saferith.Nat).SetBig(composite, composite.BitLen()))

	// This should create a ModulusOdd (uses BoringSSL)
	mComposite, ok := numct.NewModulus(compositeNat)
	if ok != ct.True {
		b.Fatal("Failed to create composite modulus")
	}

	// ModulusBasic for comparison
	mCompositeBasic := &numct.ModulusBasic{
		ModulusOddBasic: numct.ModulusOddBasic{
			ModulusOddPrimeBasic: *(*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(compositeNat))),
		},
	}

	b.Run("ModulusOdd_BoringSSL", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mComposite.ModInv(&out, x)
		}
	})

	b.Run("ModulusBasic_Saferith", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mCompositeBasic.ModInv(&out, x)
		}
	})
}

// Benchmark ModInv with different bit sizes
func BenchmarkModInv_BitSizes(b *testing.B) {
	bitSizes := []int{256, 512, 1024, 2048, 3072}

	for _, bits := range bitSizes {
		b.Run(fmt.Sprintf("%d_bits", bits), func(b *testing.B) {
			// Generate prime of specified bit size
			p, _ := rand.Prime(rand.Reader, bits)
			pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))

			m, ok := numct.NewModulusOddPrime(pNat)
			if ok != ct.True {
				b.Fatal("Failed to create ModulusOddPrime")
			}

			// Test value
			testVal := big.NewInt(0).SetBytes([]byte("test value for inverse"))
			x := newNatFromBig(testVal)
			var out numct.Nat

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.ModInv(&out, x)
			}
		})
	}
}

// BenchmarkModInv_RSA_Paillier compares ModInv performance for RSA/Paillier sizes
func BenchmarkModInv_RSA_Paillier(b *testing.B) {
	// Common RSA/Paillier modulus sizes
	bitSizes := []int{
		1024, // RSA-1024
		2048, // RSA-2048, Paillier-1024 (n^2)
		3072, // RSA-3072
		4096, // RSA-4096, Paillier-2048 (n^2)
	}

	for _, bits := range bitSizes {
		b.Run(fmt.Sprintf("Prime_%d_bits", bits), func(b *testing.B) {
			// Generate a prime of specified bit size
			p, _ := rand.Prime(rand.Reader, bits)
			pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))

			// Create test value that's coprime to p
			testVal, _ := rand.Prime(rand.Reader, bits/2)
			x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
			var out numct.Nat

			b.Run("BoringSSL", func(b *testing.B) {
				// ModulusOddPrime uses BoringSSL
				m, ok := numct.NewModulusOddPrime(pNat)
				if ok != ct.True {
					b.Fatal("Failed to create ModulusOddPrime")
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					m.ModInv(&out, x)
				}
			})

			b.Run("Saferith", func(b *testing.B) {
				// ModulusOddPrimeBasic uses saferith
				m := (*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(pNat)))

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					m.ModInv(&out, x)
				}
			})
		})
	}

	// Test with composite (RSA-like) moduli
	for _, bits := range bitSizes {
		b.Run(fmt.Sprintf("Composite_%d_bits", bits), func(b *testing.B) {
			// Generate two primes for RSA-like composite
			p1, _ := rand.Prime(rand.Reader, bits/2)
			p2, _ := rand.Prime(rand.Reader, bits/2)
			n := new(big.Int).Mul(p1, p2)
			nNat := (*numct.Nat)(new(saferith.Nat).SetBig(n, n.BitLen()))

			// Create test value coprime to n
			var testVal *big.Int
			for {
				testVal, _ = rand.Prime(rand.Reader, bits/3)
				if new(big.Int).GCD(nil, nil, testVal, n).Cmp(big.NewInt(1)) == 0 {
					break
				}
			}
			x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
			var out numct.Nat

			b.Run("BoringSSL", func(b *testing.B) {
				// ModulusOdd uses BoringSSL
				m, ok := numct.NewModulusOdd(nNat)
				if ok != ct.True {
					b.Fatal("Failed to create ModulusOdd")
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					m.ModInv(&out, x)
				}
			})

			b.Run("Saferith", func(b *testing.B) {
				// ModulusBasic uses saferith
				m := &numct.ModulusBasic{
					ModulusOddBasic: numct.ModulusOddBasic{
						ModulusOddPrimeBasic: *(*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(nNat))),
					},
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					m.ModInv(&out, x)
				}
			})
		})
	}
}

// BenchmarkModInv_SaferithOnly compares Saferith performance at different sizes
func BenchmarkModInv_SaferithOnly(b *testing.B) {
	// Common RSA/Paillier modulus sizes
	bitSizes := []int{
		1024, // RSA-1024
		2048, // RSA-2048
		3072, // RSA-3072
		4096, // RSA-4096
	}

	for _, bits := range bitSizes {
		b.Run(fmt.Sprintf("Prime_%d_bits", bits), func(b *testing.B) {
			// Generate a prime of specified bit size
			p, _ := rand.Prime(rand.Reader, bits)
			pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))

			// Create test value that's coprime to p
			testVal, _ := rand.Prime(rand.Reader, bits/2)
			x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
			var out numct.Nat

			// ModulusOddPrimeBasic uses saferith
			m := (*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(pNat)))

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.ModInv(&out, x)
			}
		})
	}

	// Test with composite (RSA-like) moduli
	for _, bits := range bitSizes {
		b.Run(fmt.Sprintf("Composite_%d_bits", bits), func(b *testing.B) {
			// Generate two primes for RSA-like composite
			p1, _ := rand.Prime(rand.Reader, bits/2)
			p2, _ := rand.Prime(rand.Reader, bits/2)
			n := new(big.Int).Mul(p1, p2)
			nNat := (*numct.Nat)(new(saferith.Nat).SetBig(n, n.BitLen()))

			// Create test value coprime to n
			var testVal *big.Int
			for {
				testVal, _ = rand.Prime(rand.Reader, bits/3)
				if new(big.Int).GCD(nil, nil, testVal, n).Cmp(big.NewInt(1)) == 0 {
					break
				}
			}
			x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
			var out numct.Nat

			// ModulusBasic uses saferith
			m := &numct.ModulusBasic{
				ModulusOddBasic: numct.ModulusOddBasic{
					ModulusOddPrimeBasic: *(*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(nNat))),
				},
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.ModInv(&out, x)
			}
		})
	}
}

// Separate focused benchmarks for ModInv

func BenchmarkModInv_Prime_1024_BoringSSL(b *testing.B) {
	p, _ := rand.Prime(rand.Reader, 1024)
	pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))
	m, _ := numct.NewModulusOddPrime(pNat)

	testVal, _ := rand.Prime(rand.Reader, 512)
	x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
	var out numct.Nat

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ModInv(&out, x)
	}
}

func BenchmarkModInv_Prime_1024_Saferith(b *testing.B) {
	p, _ := rand.Prime(rand.Reader, 1024)
	pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))
	m := (*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(pNat)))

	testVal, _ := rand.Prime(rand.Reader, 512)
	x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
	var out numct.Nat

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ModInv(&out, x)
	}
}

func BenchmarkModInv_Prime_2048_BoringSSL(b *testing.B) {
	p, _ := rand.Prime(rand.Reader, 2048)
	pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))
	m, _ := numct.NewModulusOddPrime(pNat)

	testVal, _ := rand.Prime(rand.Reader, 1024)
	x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
	var out numct.Nat

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ModInv(&out, x)
	}
}

func BenchmarkModInv_Prime_2048_Saferith(b *testing.B) {
	p, _ := rand.Prime(rand.Reader, 2048)
	pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))
	m := (*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(pNat)))

	testVal, _ := rand.Prime(rand.Reader, 1024)
	x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
	var out numct.Nat

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ModInv(&out, x)
	}
}

func BenchmarkModInv_Prime_3072_BoringSSL(b *testing.B) {
	p, _ := rand.Prime(rand.Reader, 3072)
	pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))
	m, _ := numct.NewModulusOddPrime(pNat)

	testVal, _ := rand.Prime(rand.Reader, 1536)
	x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
	var out numct.Nat

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ModInv(&out, x)
	}
}

func BenchmarkModInv_Prime_3072_Saferith(b *testing.B) {
	p, _ := rand.Prime(rand.Reader, 3072)
	pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))
	m := (*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(pNat)))

	testVal, _ := rand.Prime(rand.Reader, 1536)
	x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
	var out numct.Nat

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ModInv(&out, x)
	}
}

func BenchmarkModInv_Composite_1024_BoringSSL(b *testing.B) {
	p1, _ := rand.Prime(rand.Reader, 512)
	p2, _ := rand.Prime(rand.Reader, 512)
	n := new(big.Int).Mul(p1, p2)
	nNat := (*numct.Nat)(new(saferith.Nat).SetBig(n, n.BitLen()))
	m, _ := numct.NewModulusOdd(nNat)

	// Find coprime value
	var testVal *big.Int
	for {
		testVal, _ = rand.Prime(rand.Reader, 341)
		if new(big.Int).GCD(nil, nil, testVal, n).Cmp(big.NewInt(1)) == 0 {
			break
		}
	}
	x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
	var out numct.Nat

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ModInv(&out, x)
	}
}

func BenchmarkModInv_Composite_1024_Saferith(b *testing.B) {
	p1, _ := rand.Prime(rand.Reader, 512)
	p2, _ := rand.Prime(rand.Reader, 512)
	n := new(big.Int).Mul(p1, p2)
	nNat := (*numct.Nat)(new(saferith.Nat).SetBig(n, n.BitLen()))
	m := &numct.ModulusBasic{
		ModulusOddBasic: numct.ModulusOddBasic{
			ModulusOddPrimeBasic: *(*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(nNat))),
		},
	}

	// Find coprime value
	var testVal *big.Int
	for {
		testVal, _ = rand.Prime(rand.Reader, 341)
		if new(big.Int).GCD(nil, nil, testVal, n).Cmp(big.NewInt(1)) == 0 {
			break
		}
	}
	x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
	var out numct.Nat

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ModInv(&out, x)
	}
}

func BenchmarkModInv_Composite_2048_BoringSSL(b *testing.B) {
	p1, _ := rand.Prime(rand.Reader, 1024)
	p2, _ := rand.Prime(rand.Reader, 1024)
	n := new(big.Int).Mul(p1, p2)
	nNat := (*numct.Nat)(new(saferith.Nat).SetBig(n, n.BitLen()))
	m, _ := numct.NewModulusOdd(nNat)

	// Find coprime value
	var testVal *big.Int
	for {
		testVal, _ = rand.Prime(rand.Reader, 683)
		if new(big.Int).GCD(nil, nil, testVal, n).Cmp(big.NewInt(1)) == 0 {
			break
		}
	}
	x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
	var out numct.Nat

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ModInv(&out, x)
	}
}

func BenchmarkModInv_Composite_2048_Saferith(b *testing.B) {
	p1, _ := rand.Prime(rand.Reader, 1024)
	p2, _ := rand.Prime(rand.Reader, 1024)
	n := new(big.Int).Mul(p1, p2)
	nNat := (*numct.Nat)(new(saferith.Nat).SetBig(n, n.BitLen()))
	m := &numct.ModulusBasic{
		ModulusOddBasic: numct.ModulusOddBasic{
			ModulusOddPrimeBasic: *(*numct.ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(nNat))),
		},
	}

	// Find coprime value
	var testVal *big.Int
	for {
		testVal, _ = rand.Prime(rand.Reader, 683)
		if new(big.Int).GCD(nil, nil, testVal, n).Cmp(big.NewInt(1)) == 0 {
			break
		}
	}
	x := (*numct.Nat)(new(saferith.Nat).SetBig(testVal, testVal.BitLen()))
	var out numct.Nat

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ModInv(&out, x)
	}
}

func TestModInv_CompositeOne(t *testing.T) {
	// Test that 1 always has inverse 1 for any modulus
	n := big.NewInt(15) // composite
	nNat := (*numct.Nat)(new(saferith.Nat).SetBig(n, n.BitLen()))

	m, ok := numct.NewModulusOdd(nNat)
	require.Equal(t, ct.True, ok)

	one := big.NewInt(1)
	oneNat := (*numct.Nat)(new(saferith.Nat).SetBig(one, one.BitLen()))

	var inv numct.Nat
	invOk := m.ModInv(&inv, oneNat)

	t.Logf("ModInv(1) mod 15: ok=%v", invOk)
	require.Equal(t, ct.True, invOk, "1 should always have an inverse")

	if invOk == ct.True {
		// Verify the inverse is correct by multiplying
		var product numct.Nat
		m.ModMul(&product, oneNat, &inv)
		require.True(t, product.Equal(oneNat) == ct.True, "1 * inv should equal 1")
	}
}
