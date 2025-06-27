package num_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

func TestMax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        num.LiftableToZ
		b        num.LiftableToZ
		expected string
	}{
		{
			name:     "Nat_Max_Same",
			a:        num.N().FromUint64(5),
			b:        num.N().FromUint64(5),
			expected: "5",
		},
		{
			name:     "Nat_Max_Different",
			a:        num.N().FromUint64(3),
			b:        num.N().FromUint64(7),
			expected: "7",
		},
		{
			name:     "NatPlus_Max",
			a:        mustNatPlus(num.NPlus().FromUint64(10)),
			b:        mustNatPlus(num.NPlus().FromUint64(20)),
			expected: "20",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := num.Max(tt.a, tt.b)
			require.Equal(t, tt.expected, result.Lift().String())
		})
	}
}

func TestMin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        num.LiftableToZ
		b        num.LiftableToZ
		expected string
	}{
		{
			name:     "Nat_Min_Same",
			a:        num.N().FromUint64(5),
			b:        num.N().FromUint64(5),
			expected: "5",
		},
		{
			name:     "Nat_Min_Different",
			a:        num.N().FromUint64(3),
			b:        num.N().FromUint64(7),
			expected: "3",
		},
		{
			name:     "NatPlus_Min",
			a:        mustNatPlus(num.NPlus().FromUint64(10)),
			b:        mustNatPlus(num.NPlus().FromUint64(20)),
			expected: "10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := num.Min(tt.a, tt.b)
			require.Equal(t, tt.expected, result.Lift().String())
		})
	}
}

func TestGCD(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.Int
		b        *num.Int
		expected string
	}{
		{
			name:     "GCD_Same",
			a:        num.Z().FromInt64(12),
			b:        num.Z().FromInt64(12),
			expected: "12",
		},
		{
			name:     "GCD_Coprime",
			a:        num.Z().FromInt64(13),
			b:        num.Z().FromInt64(17),
			expected: "1",
		},
		{
			name:     "GCD_Common_Factor",
			a:        num.Z().FromInt64(12),
			b:        num.Z().FromInt64(18),
			expected: "6",
		},
		{
			name:     "GCD_One_Is_Zero",
			a:        num.Z().Zero(),
			b:        num.Z().FromInt64(15),
			expected: "15",
		},
		{
			name:     "GCD_Both_Zero",
			a:        num.Z().Zero(),
			b:        num.Z().Zero(),
			expected: "0",
		},
		{
			name:     "GCD_Large_Numbers",
			a:        num.Z().FromInt64(1071),
			b:        num.Z().FromInt64(462),
			expected: "21", // GCD(1071, 462) = 21
		},
		{
			name:     "GCD_Negative",
			a:        num.Z().FromInt64(-12),
			b:        num.Z().FromInt64(18),
			expected: "6",
		},
		{
			name:     "GCD_Both_Negative",
			a:        num.Z().FromInt64(-12),
			b:        num.Z().FromInt64(-18),
			expected: "6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := num.GCD(tt.a, tt.b)
			require.Equal(t, tt.expected, result.String())
		})
	}

	t.Run("GCD_Nil_Panics", func(t *testing.T) {
		t.Parallel()

		require.Panics(t, func() {
			num.GCD(nil, num.Z().One())
		})

		require.Panics(t, func() {
			num.GCD(num.Z().One(), nil)
		})
	})
}

func TestLCM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		a           *num.Int
		b           *num.Int
		expected    string
		expectError bool
	}{
		{
			name:     "LCM_Same",
			a:        num.Z().FromInt64(12),
			b:        num.Z().FromInt64(12),
			expected: "12",
		},
		{
			name:     "LCM_Coprime",
			a:        num.Z().FromInt64(13),
			b:        num.Z().FromInt64(17),
			expected: "221", // 13 * 17 = 221
		},
		{
			name:     "LCM_Common_Factor",
			a:        num.Z().FromInt64(12),
			b:        num.Z().FromInt64(18),
			expected: "36", // LCM(12, 18) = 36
		},
		{
			name:     "LCM_Small",
			a:        num.Z().FromInt64(4),
			b:        num.Z().FromInt64(6),
			expected: "12", // LCM(4, 6) = 12
		},
		{
			name:     "LCM_One_Is_One",
			a:        num.Z().One(),
			b:        num.Z().FromInt64(15),
			expected: "15",
		},
		{
			name:        "LCM_One_Is_Zero",
			a:           num.Z().Zero(),
			b:           num.Z().FromInt64(15),
			expected:    "0",
			expectError: false, // LCM(0, n) = 0
		},
		{
			name:     "LCM_Negative",
			a:        num.Z().FromInt64(-12),
			b:        num.Z().FromInt64(18),
			expected: "36", // LCM uses absolute values
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := num.LCM(tt.a, tt.b)
			
			if tt.expectError {
				require.Error(t, err)
				return
			}
			
			require.NoError(t, err)
			require.Equal(t, tt.expected, result.String())
		})
	}

	t.Run("LCM_Nil_Panics", func(t *testing.T) {
		t.Parallel()

		require.Panics(t, func() {
			num.LCM(nil, num.Z().One())
		})

		require.Panics(t, func() {
			num.LCM(num.Z().One(), nil)
		})
	})
}

func TestPrimeFactorisation(t *testing.T) {
	t.Parallel()

	t.Run("NewPrimeFactorisation", func(t *testing.T) {
		t.Parallel()

		// Test with Uint
		zn, err := num.NewZn(cardinal.New(100))
		require.NoError(t, err)

		// Create prime factorization for 12 = 2^2 * 3
		factors := hashmap.NewComparable[*num.NatPlus, *num.Nat]()
		
		two, err := num.NPlus().FromUint64(2)
		require.NoError(t, err)
		three, err := num.NPlus().FromUint64(3)
		require.NoError(t, err)
		
		factors.Put(two, num.N().FromUint64(2))   // 2^2
		factors.Put(three, num.N().FromUint64(1)) // 3^1

		twelve := zn.FromUint64(12)
		pf, err := num.NewPrimeFactorisation(twelve, factors.Freeze())
		require.NoError(t, err)
		require.NotNil(t, pf)

		// Test getters
		require.Equal(t, twelve, pf.N())
		
		// Count prime factors
		count := 0
		for range pf.PrimeFactors().Iter() {
			count++
		}
		require.Equal(t, 2, count)
		
		require.False(t, pf.IsPrimeProduct()) // Has 2^2, not just primes to power 1
	})

	t.Run("IsPrimeProduct", func(t *testing.T) {
		t.Parallel()

		zn, err := num.NewZn(cardinal.New(100))
		require.NoError(t, err)

		// Test prime product: 30 = 2 * 3 * 5 (all to power 1)
		factors := hashmap.NewComparable[*num.NatPlus, *num.Nat]()
		
		two, err := num.NPlus().FromUint64(2)
		require.NoError(t, err)
		three, err := num.NPlus().FromUint64(3)
		require.NoError(t, err)
		five, err := num.NPlus().FromUint64(5)
		require.NoError(t, err)
		
		factors.Put(two, num.N().One())
		factors.Put(three, num.N().One())
		factors.Put(five, num.N().One())

		thirty := zn.FromUint64(30)
		pf, err := num.NewPrimeFactorisation(thirty, factors.Freeze())
		require.NoError(t, err)
		require.True(t, pf.IsPrimeProduct())
	})

	t.Run("Error_Cases", func(t *testing.T) {
		t.Parallel()

		zn, err := num.NewZn(cardinal.New(100))
		require.NoError(t, err)

		// Nil factors
		_, err = num.NewPrimeFactorisation(zn.FromUint64(12), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "argument")

		// Identity element (zero)
		factors := hashmap.NewComparable[*num.NatPlus, *num.Nat]()
		two, err := num.NPlus().FromUint64(2)
		require.NoError(t, err)
		factors.Put(two, num.N().One())
		
		_, err = num.NewPrimeFactorisation(zn.Zero(), factors.Freeze())
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not be identity")

		// Non-prime factor
		factors2 := hashmap.NewComparable[*num.NatPlus, *num.Nat]()
		four, err := num.NPlus().FromUint64(4) // 4 is not prime
		require.NoError(t, err)
		factors2.Put(four, num.N().One())
		
		_, err = num.NewPrimeFactorisation(zn.FromUint64(4), factors2.Freeze())
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be prime")
	})
}

func TestEulerTotientFunction(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(1000))
	require.NoError(t, err)

	tests := []struct {
		name        string
		n           uint64
		factors     map[uint64]uint64 // prime -> exponent
		expected    uint64
	}{
		{
			name:     "Prime_Number",
			n:        7,
			factors:  map[uint64]uint64{7: 1},
			expected: 6, // φ(7) = 6
		},
		{
			name:     "Prime_Power",
			n:        9, // 3^2
			factors:  map[uint64]uint64{3: 2},
			expected: 6, // φ(3^2) = 3^2 - 3^1 = 9 - 3 = 6
		},
		{
			name:     "Two_Primes",
			n:        15, // 3 * 5
			factors:  map[uint64]uint64{3: 1, 5: 1},
			expected: 8, // φ(15) = φ(3) * φ(5) = 2 * 4 = 8
		},
		{
			name:     "Prime_And_Power",
			n:        12, // 2^2 * 3
			factors:  map[uint64]uint64{2: 2, 3: 1},
			expected: 4, // φ(12) = φ(4) * φ(3) = 2 * 2 = 4
		},
		{
			name:     "Three_Primes",
			n:        30, // 2 * 3 * 5
			factors:  map[uint64]uint64{2: 1, 3: 1, 5: 1},
			expected: 8, // φ(30) = φ(2) * φ(3) * φ(5) = 1 * 2 * 4 = 8
		},
		{
			name:     "Large_Prime_Power",
			n:        25, // 5^2
			factors:  map[uint64]uint64{5: 2},
			expected: 20, // φ(25) = 5^2 - 5^1 = 25 - 5 = 20
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Build prime factorization
			factors := hashmap.NewComparable[*num.NatPlus, *num.Nat]()
			for prime, exp := range tt.factors {
				p, err := num.NPlus().FromUint64(prime)
				require.NoError(t, err)
				factors.Put(p, num.N().FromUint64(exp))
			}

			n := zn.FromUint64(tt.n)
			pf, err := num.NewPrimeFactorisation(n, factors.Freeze())
			require.NoError(t, err)

			result, err := num.EulerTotient(pf)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result.Cardinal().Uint64())
		})
	}

	t.Run("Nil_PrimeFactorisation", func(t *testing.T) {
		t.Parallel()

		_, err := num.EulerTotient[*num.Uint](nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "argument")
	})
}