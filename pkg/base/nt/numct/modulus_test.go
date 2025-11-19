package numct_test

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func newNatFromBig(b *big.Int) *numct.Nat {
	return (*numct.Nat)(new(saferith.Nat).SetBig(b, b.BitLen()))
}

func newModulus(p *big.Int) *numct.Modulus {
	pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))
	m, ok := numct.NewModulus(pNat)
	if ok != ct.True {
		panic("failed to create Modulus")
	}
	return m
}

func TestNewModulusFromNat(t *testing.T) {
	t.Run("odd prime", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(7))
		m, ok := numct.NewModulus(p)
		assert.Equal(t, ct.True, ok, "Failed to create modulus")
		assert.NotNil(t, m)
	})

	t.Run("odd composite", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(15)) // 3*5, not prime
		m, ok := numct.NewModulus(p)
		assert.Equal(t, ct.True, ok, "Failed to create modulus")
		assert.NotNil(t, m)
	})

	t.Run("even number", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(10))
		m, ok := numct.NewModulus(p)
		assert.Equal(t, ct.True, ok, "Failed to create modulus")
		assert.NotNil(t, m)
	})

	t.Run("zero should fail", func(t *testing.T) {
		p := newNatFromBig(big.NewInt(0))
		_, ok := numct.NewModulus(p)
		assert.Equal(t, ct.False, ok, "Should not create modulus for zero")
	})
}

func TestModulus_BasicOperations(t *testing.T) {
	m := newModulus(big.NewInt(7))

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
			t.Run(tt.name, func(t *testing.T) {
				x := newNatFromBig(big.NewInt(tt.x))
				out := newNatFromBig(big.NewInt(0))

				m.ModNeg(out, x)
				assert.Equal(t, uint64(tt.want), out.Uint64())
			})
		}
	})
}

func TestModulus_Inv(t *testing.T) {
	m := newModulus(big.NewInt(7))

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
		{"inv of 0", 0, 0}, // Special case
	}

	for _, tt := range tests {
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

func TestModulus_Sqrt(t *testing.T) {
	t.Run("prime modulus", func(t *testing.T) {
		m := newModulus(big.NewInt(7))

		tests := []struct {
			name     string
			x        int64
			wantOk   ct.Bool
		}{
			{"sqrt of 0", 0, ct.True},
			{"sqrt of 1", 1, ct.True},
			{"sqrt of 2", 2, ct.True},     // 3^2 = 9 ≡ 2 mod 7 or 4^2 = 16 ≡ 2 mod 7
			{"sqrt of 4", 4, ct.True},     // 2^2 = 4
			{"no sqrt of 3", 3, ct.False}, // 3 is not a quadratic residue mod 7
			{"no sqrt of 5", 5, ct.False}, // 5 is not a quadratic residue mod 7
			{"no sqrt of 6", 6, ct.False}, // 6 is not a quadratic residue mod 7
		}

		for _, tt := range tests {
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
				}
			})
		}
	})

	t.Run("composite modulus", func(t *testing.T) {
		m := newModulus(big.NewInt(10))

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
			t.Run(tt.name, func(t *testing.T) {
				x := newNatFromBig(big.NewInt(tt.x))
				out := newNatFromBig(big.NewInt(0))

				ok := m.ModSqrt(out, x)
				assert.Equal(t, tt.wantOk, ok)

				if ok == ct.True {
					assert.Equal(t, uint64(tt.wantRoot), out.Uint64())

					// Verify that out^2 ≡ x mod 10
					squared := newNatFromBig(big.NewInt(0))
					m.ModMul(squared, out, out)
					xMod := newNatFromBig(big.NewInt(0))
					m.Mod(xMod, x)
					assert.Equal(t, xMod.Uint64(), squared.Uint64(), "sqrt(x)^2 should equal x mod m")
				}
			})
		}
	})
}

func TestModulus_Div(t *testing.T) {
	m := newModulus(big.NewInt(7))

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

func TestModulus_Properties(t *testing.T) {
	p := big.NewInt(97)
	m := newModulus(p)

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
			t.Run(tt.name, func(t *testing.T) {
				x := newNatFromBig(big.NewInt(tt.x))
				got := m.IsUnit(x)
				assert.Equal(t, tt.want, got)
			})
		}
	})
}

func TestModulus_Exp(t *testing.T) {
	m := newModulus(big.NewInt(7))

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
		t.Run(tt.name, func(t *testing.T) {
			base := newNatFromBig(big.NewInt(tt.base))
			exp := newNatFromBig(big.NewInt(tt.exp))
			out := newNatFromBig(big.NewInt(0))

			m.ModExp(out, base, exp)
			assert.Equal(t, uint64(tt.want), out.Uint64())
		})
	}
}

func TestModulus_EvenModulus(t *testing.T) {
	// Test operations with even modulus
	m := newModulus(big.NewInt(10))

	t.Run("ModExp", func(t *testing.T) {
		base := newNatFromBig(big.NewInt(3))
		exp := newNatFromBig(big.NewInt(4))
		out := newNatFromBig(big.NewInt(0))

		m.ModExp(out, base, exp)
		// 3^4 = 81, 81 mod 10 = 1
		assert.Equal(t, uint64(1), out.Uint64())
	})

	t.Run("ModInv", func(t *testing.T) {
		// 3 is coprime to 10, should have an inverse
		x := newNatFromBig(big.NewInt(3))
		out := newNatFromBig(big.NewInt(0))

		ok := m.ModInv(out, x)
		assert.Equal(t, ct.True, ok)

		// Verify 3 * inv ≡ 1 mod 10
		// 3 * 7 = 21 ≡ 1 mod 10
		product := newNatFromBig(big.NewInt(0))
		m.ModMul(product, x, out)
		assert.Equal(t, uint64(1), product.Uint64())
	})

	t.Run("ModDiv even modulus", func(t *testing.T) {
		// Test division with even modulus using extended GCD
		x := newNatFromBig(big.NewInt(6))
		y := newNatFromBig(big.NewInt(3))
		out := newNatFromBig(big.NewInt(0))

		ok := m.ModDiv(out, x, y)
		assert.Equal(t, ct.True, ok)

		// Verify out * y ≡ x mod 10
		product := newNatFromBig(big.NewInt(0))
		m.ModMul(product, out, y)
		xMod := newNatFromBig(big.NewInt(0))
		m.Mod(xMod, x)
		assert.Equal(t, xMod.Uint64(), product.Uint64())
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
			pBig, _ := crand.Prime(crand.Reader, tc.primeBits)
			p := (*numct.Nat)(new(saferith.Nat).SetBig(pBig, tc.primeBits).Resize(tc.primeBits))

			// Create Modulus with cached Montgomery context
			pMod, ok := numct.NewModulus(p)
			require.Equal(t, ct.True, ok)

			// Generate test data
			bases := make([]*numct.Nat, tc.ops)
			exps := make([]*numct.Nat, tc.ops)
			for i := range tc.ops {
				base, _ := crand.Int(crand.Reader, pBig)
				bases[i] = (*numct.Nat)(new(saferith.Nat).SetBig(base, tc.primeBits).Resize(tc.primeBits))

				exp, _ := crand.Int(crand.Reader, pBig)
				exps[i] = (*numct.Nat)(new(saferith.Nat).SetBig(exp, tc.primeBits).Resize(tc.primeBits))
			}

			result := (*numct.Nat)(new(saferith.Nat))

			// Test ModExp with reusing modulus (cached Montgomery context)
			start := time.Now()
			for i := range tc.ops {
				pMod.ModExp(result, bases[i], exps[i])
			}
			reuseTime := time.Since(start)

			// Test with recreating the modulus each time (no cache benefit)
			start = time.Now()
			for i := range tc.ops {
				newPMod, _ := numct.NewModulus(p)
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
	m := newModulus(p)

	x := newNatFromBig(big.NewInt(123))
	y := newNatFromBig(big.NewInt(456))
	out := newNatFromBig(big.NewInt(0))

	b.Run("Add", func(b *testing.B) {
		for range b.N {
			m.ModAdd(out, x, y)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for range b.N {
			m.ModMul(out, x, y)
		}
	})

	b.Run("Inv", func(b *testing.B) {
		for range b.N {
			m.ModInv(out, x)
		}
	})

	b.Run("Sqrt", func(b *testing.B) {
		// Use a quadratic residue
		qr := newNatFromBig(big.NewInt(4))
		for range b.N {
			m.ModSqrt(out, qr)
		}
	})

	b.Run("Exp", func(b *testing.B) {
		exp := newNatFromBig(big.NewInt(100))
		for range b.N {
			m.ModExp(out, x, exp)
		}
	})
}

func TestModSymmetric(t *testing.T) {
	// Test with prime modulus 11
	p := big.NewInt(11)
	m := newModulus(p)

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
	t.Run("Prime modulus", func(t *testing.T) {
		// Test with prime modulus 13
		p := big.NewInt(13)
		m := newModulus(p)

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
		m := newModulus(n)

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

// Benchmark ModInv with different bit sizes
func BenchmarkModInv_BitSizes(b *testing.B) {
	bitSizes := []int{256, 512, 1024, 2048, 3072}

	for _, bits := range bitSizes {
		b.Run(fmt.Sprintf("%d_bits", bits), func(b *testing.B) {
			// Generate prime of specified bit size
			p, _ := crand.Prime(crand.Reader, bits)
			pNat := (*numct.Nat)(new(saferith.Nat).SetBig(p, p.BitLen()))

			m, ok := numct.NewModulus(pNat)
			if ok != ct.True {
				b.Fatal("Failed to create Modulus")
			}

			// Test value
			testVal := big.NewInt(0).SetBytes([]byte("test value for inverse"))
			x := newNatFromBig(testVal)
			var out numct.Nat

			b.ResetTimer()
			for range b.N {
				m.ModInv(&out, x)
			}
		})
	}
}
