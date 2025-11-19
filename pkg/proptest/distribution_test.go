package proptest

import (
	"crypto/rand"
	"testing"
)

// TestDiracDistribution tests that Dirac distribution always returns the same value
func TestDiracDistribution(t *testing.T) {
	t.Parallel()

	t.Run("Int", func(t *testing.T) {
		dist := DiracDistribution(42)
		for range 100 {
			if got := dist.Draw(); got != 42 {
				t.Errorf("DiracDistribution(42).Draw() = %d, want 42", got)
			}
		}
	})

	t.Run("String", func(t *testing.T) {
		expected := "constant"
		dist := DiracDistribution(expected)
		for range 100 {
			if got := dist.Draw(); got != expected {
				t.Errorf("DiracDistribution(%q).Draw() = %q, want %q", expected, got, expected)
			}
		}
	})

	t.Run("Slice", func(t *testing.T) {
		expected := []int{1, 2, 3}
		dist := DiracDistribution(expected)
		for range 100 {
			got := dist.Draw()
			if len(got) != len(expected) {
				t.Errorf("length mismatch: got %d, want %d", len(got), len(expected))
				continue
			}
			for i := range got {
				if got[i] != expected[i] {
					t.Errorf("element %d: got %d, want %d", i, got[i], expected[i])
				}
			}
		}
	})
}

// TestUniformDistribution tests that uniform distribution generates values in range
func TestUniformDistribution(t *testing.T) {
	t.Parallel()

	t.Run("BasicRange", func(t *testing.T) {
		lo, hi := 10, 20
		dist := UniformDistribution(lo, hi)

		// Test that all values are in range
		for range 1000 {
			v := dist.Draw()
			if v < lo || v >= hi {
				t.Errorf("UniformDistribution(%d, %d).Draw() = %d, want value in [%d, %d)",
					lo, hi, v, lo, hi)
			}
		}
	})

	t.Run("Coverage", func(t *testing.T) {
		// Test that we eventually see all values in a small range
		lo, hi := 0, 5
		dist := UniformDistribution(lo, hi)

		seen := make(map[int]bool)
		for range 1000 {
			v := dist.Draw()
			seen[v] = true
		}

		// With 1000 draws from [0, 5), we should see all values
		for i := lo; i < hi; i++ {
			if !seen[i] {
				t.Errorf("value %d not seen after 1000 draws", i)
			}
		}
	})

	t.Run("SingleValue", func(t *testing.T) {
		// When hi-lo == 1, should always return lo
		dist := UniformDistribution(5, 6)
		for range 100 {
			if v := dist.Draw(); v != 5 {
				t.Errorf("UniformDistribution(5, 6).Draw() = %d, want 5", v)
			}
		}
	})

	t.Run("NegativeRange", func(t *testing.T) {
		lo, hi := -10, 0
		dist := UniformDistribution(lo, hi)

		for range 100 {
			v := dist.Draw()
			if v < lo || v >= hi {
				t.Errorf("UniformDistribution(%d, %d).Draw() = %d, want value in [%d, %d)",
					lo, hi, v, lo, hi)
			}
		}
	})
}

// TestFiniteSupportDistribution tests that finite support distribution picks from the given set
func TestFiniteSupportDistribution(t *testing.T) {
	t.Parallel()

	t.Run("IntSlice", func(t *testing.T) {
		elements := []int{1, 3, 5, 7, 9}
		dist := FiniteSupportDistribution(elements)

		validSet := make(map[int]bool)
		for _, e := range elements {
			validSet[e] = true
		}

		for range 1000 {
			v := dist.Draw()
			if !validSet[v] {
				t.Errorf("FiniteSupportDistribution(%v).Draw() = %d, not in valid set", elements, v)
			}
		}
	})

	t.Run("Coverage", func(t *testing.T) {
		elements := []string{"a", "b", "c"}
		dist := FiniteSupportDistribution(elements)

		seen := make(map[string]bool)
		for range 1000 {
			v := dist.Draw()
			seen[v] = true
		}

		// Should see all elements
		for _, e := range elements {
			if !seen[e] {
				t.Errorf("element %q not seen after 1000 draws", e)
			}
		}
	})

	t.Run("SingleElement", func(t *testing.T) {
		elements := []int{42}
		dist := FiniteSupportDistribution(elements)

		for range 100 {
			if v := dist.Draw(); v != 42 {
				t.Errorf("FiniteSupportDistribution([42]).Draw() = %d, want 42", v)
			}
		}
	})
}

// TestRepeated tests the Repeated combinator
func TestRepeated(t *testing.T) {
	t.Parallel()

	t.Run("Length", func(t *testing.T) {
		dist := Repeated(UniformDistribution(0, 100), 10)

		for range 100 {
			v := dist.Draw()
			if len(v) != 10 {
				t.Errorf("Repeated(_, 10).Draw() length = %d, want 10", len(v))
			}
		}
	})

	t.Run("AllInRange", func(t *testing.T) {
		lo, hi := 5, 15
		length := 20
		dist := Repeated(UniformDistribution(lo, hi), length)

		v := dist.Draw()
		for i, elem := range v {
			if elem < lo || elem >= hi {
				t.Errorf("element %d: got %d, want value in [%d, %d)", i, elem, lo, hi)
			}
		}
	})

	t.Run("ZeroLength", func(t *testing.T) {
		dist := Repeated(UniformDistribution(0, 100), 0)

		v := dist.Draw()
		if len(v) != 0 {
			t.Errorf("Repeated(_, 0).Draw() length = %d, want 0", len(v))
		}
	})
}

// TestOneOf tests the OneOf combinator
func TestOneOf(t *testing.T) {
	t.Parallel()

	t.Run("SingleDistribution", func(t *testing.T) {
		dist := OneOf(DiracDistribution(42))

		for range 100 {
			if v := dist.Draw(); v != 42 {
				t.Errorf("OneOf(Dirac(42)).Draw() = %d, want 42", v)
			}
		}
	})

	t.Run("MultipleDistributions", func(t *testing.T) {
		dist := OneOf(
			DiracDistribution(1),
			DiracDistribution(2),
			DiracDistribution(3),
		)

		seen := make(map[int]bool)
		for range 1000 {
			v := dist.Draw()
			if v < 1 || v > 3 {
				t.Errorf("OneOf().Draw() = %d, want value in {1, 2, 3}", v)
			}
			seen[v] = true
		}

		// Should see all three values eventually
		for i := 1; i <= 3; i++ {
			if !seen[i] {
				t.Errorf("value %d not seen after 1000 draws", i)
			}
		}
	})

	t.Run("Panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("OneOf() with no distributions should panic")
			}
		}()

		_ = OneOf[int]()
	})
}

// TestMap tests the Map combinator
func TestMap(t *testing.T) {
	t.Parallel()

	t.Run("IntToString", func(t *testing.T) {
		dist := Map(UniformDistribution(0, 10), func(i int) string {
			return string(rune('a' + i))
		})

		for range 100 {
			v := dist.Draw()
			if len(v) != 1 {
				t.Errorf("mapped string length = %d, want 1", len(v))
			}
			if v[0] < 'a' || v[0] >= 'a'+10 {
				t.Errorf("mapped string = %q, want char in [a, k)", v)
			}
		}
	})

	t.Run("Doubling", func(t *testing.T) {
		dist := Map(UniformDistribution(1, 11), func(i int) int {
			return i * 2
		})

		for range 100 {
			v := dist.Draw()
			if v < 2 || v >= 22 || v%2 != 0 {
				t.Errorf("Map(_, double).Draw() = %d, want even value in [2, 22)", v)
			}
		}
	})
}

// TestBind tests the Bind combinator
func TestBind(t *testing.T) {
	t.Parallel()

	t.Run("DependentDistribution", func(t *testing.T) {
		// Draw a number n, then draw from [0, n)
		dist := Bind(UniformDistribution(1, 10), func(n int) Distribution[int] {
			return UniformDistribution(0, n)
		})

		// Just verify it doesn't panic and produces reasonable values
		for range 100 {
			v := dist.Draw()
			if v < 0 || v >= 10 {
				t.Errorf("Bind().Draw() = %d, want value in [0, 10)", v)
			}
		}
	})

	t.Run("ChainedDraws", func(t *testing.T) {
		// Draw a boolean, if true return 1, else return 0
		dist := Bind(BernoulliDistribution(0.5), func(b bool) Distribution[int] {
			if b {
				return DiracDistribution(1)
			}
			return DiracDistribution(0)
		})

		seen := make(map[int]bool)
		for range 1000 {
			v := dist.Draw()
			if v != 0 && v != 1 {
				t.Errorf("Bind().Draw() = %d, want 0 or 1", v)
			}
			seen[v] = true
		}

		// Should see both values
		if !seen[0] || !seen[1] {
			t.Errorf("did not see both 0 and 1 in 1000 draws")
		}
	})
}

// TestFilter tests the Filter combinator
func TestFilter(t *testing.T) {
	t.Parallel()

	t.Run("EvenNumbers", func(t *testing.T) {
		dist := Filter(UniformDistribution(0, 100), func(i int) bool {
			return i%2 == 0
		}, 1000)

		for range 100 {
			v := dist.Draw()
			if v%2 != 0 {
				t.Errorf("Filter(even).Draw() = %d, want even number", v)
			}
		}
	})

	t.Run("PanicOnTooSelective", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Filter with impossible predicate should panic")
			}
		}()

		// Predicate that's never satisfied
		dist := Filter(UniformDistribution(0, 10), func(i int) bool {
			return i > 100
		}, 10)

		_ = dist.Draw()
	})

	t.Run("AlwaysTrue", func(t *testing.T) {
		dist := Filter(UniformDistribution(0, 10), func(i int) bool {
			return true
		}, 10)

		for range 100 {
			v := dist.Draw()
			if v < 0 || v >= 10 {
				t.Errorf("Filter(always true).Draw() = %d, want value in [0, 10)", v)
			}
		}
	})
}

// TestBernoulliDistribution tests the Bernoulli distribution
func TestBernoulliDistribution(t *testing.T) {
	t.Parallel()

	t.Run("AlwaysFalse", func(t *testing.T) {
		dist := BernoulliDistribution(0.0)

		for range 100 {
			if v := dist.Draw(); v {
				t.Errorf("BernoulliDistribution(0.0).Draw() = true, want false")
			}
		}
	})

	t.Run("AlwaysTrue", func(t *testing.T) {
		dist := BernoulliDistribution(1.0)

		for range 100 {
			if v := dist.Draw(); !v {
				t.Errorf("BernoulliDistribution(1.0).Draw() = false, want true")
			}
		}
	})

	t.Run("HalfProbability", func(t *testing.T) {
		dist := BernoulliDistribution(0.5)

		trueCount := 0
		n := 10000
		for range n {
			if dist.Draw() {
				trueCount++
			}
		}

		// Should be roughly 50% (allow 45-55% range for randomness)
		ratio := float64(trueCount) / float64(n)
		if ratio < 0.45 || ratio > 0.55 {
			t.Errorf("BernoulliDistribution(0.5) produced %d/%d (%.2f%%) true values, want ~50%%",
				trueCount, n, ratio*100)
		}
	})

	t.Run("LowProbability", func(t *testing.T) {
		dist := BernoulliDistribution(0.1)

		trueCount := 0
		n := 10000
		for range n {
			if dist.Draw() {
				trueCount++
			}
		}

		// Should be roughly 10% (allow 7-13% range)
		ratio := float64(trueCount) / float64(n)
		if ratio < 0.07 || ratio > 0.13 {
			t.Errorf("BernoulliDistribution(0.1) produced %d/%d (%.2f%%) true values, want ~10%%",
				trueCount, n, ratio*100)
		}
	})
}

// TestOptionalDistribution tests the OptionalDistribution
func TestOptionalDistribution(t *testing.T) {
	t.Parallel()

	t.Run("AlwaysNone", func(t *testing.T) {
		dist := OptionalDistribution(UniformDistribution(0, 100), 0.0)

		for range 100 {
			if v := dist.Draw(); v != nil {
				t.Errorf("OptionalDistribution(_, 0.0).Draw() = %v, want nil", v)
			}
		}
	})

	t.Run("AlwaysSome", func(t *testing.T) {
		dist := OptionalDistribution(UniformDistribution(0, 100), 1.0)

		for range 100 {
			v := dist.Draw()
			if v == nil {
				t.Errorf("OptionalDistribution(_, 1.0).Draw() = nil, want non-nil")
			} else if *v < 0 || *v >= 100 {
				t.Errorf("OptionalDistribution(_, 1.0).Draw() = %d, want value in [0, 100)", *v)
			}
		}
	})

	t.Run("HalfProbability", func(t *testing.T) {
		dist := OptionalDistribution(DiracDistribution(42), 0.5)

		noneCount := 0
		someCount := 0
		n := 10000
		for range n {
			v := dist.Draw()
			if v == nil {
				noneCount++
			} else {
				someCount++
				if *v != 42 {
					t.Errorf("OptionalDistribution().Draw() = %d, want 42", *v)
				}
			}
		}

		// Should be roughly 50% each (allow 45-55% range)
		noneRatio := float64(noneCount) / float64(n)
		if noneRatio < 0.45 || noneRatio > 0.55 {
			t.Errorf("OptionalDistribution(_, 0.5) produced %d/%d (%.2f%%) nil values, want ~50%%",
				noneCount, n, noneRatio*100)
		}
	})
}

// TestRuneDistribution tests rune generation
func TestRuneDistribution(t *testing.T) {
	t.Parallel()

	t.Run("Alphabetical", func(t *testing.T) {
		dist := NewRuneDistribution(Alphabetical)

		for range 100 {
			r := dist.Draw()
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
				t.Errorf("NewRuneDistribution(Alphabetical).Draw() = %c, want alphabetical char", r)
			}
		}
	})

	t.Run("Numerical", func(t *testing.T) {
		dist := NewRuneDistribution(Numerical)

		for range 100 {
			r := dist.Draw()
			if r < '0' || r > '9' {
				t.Errorf("NewRuneDistribution(Numerical).Draw() = %c, want digit", r)
			}
		}
	})

	t.Run("AlphaNumeric", func(t *testing.T) {
		dist := NewRuneDistribution(AlphaNumeric)

		for range 100 {
			r := dist.Draw()
			isAlpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			isDigit := r >= '0' && r <= '9'
			if !isAlpha && !isDigit {
				t.Errorf("NewRuneDistribution(AlphaNumeric).Draw() = %c, want alphanumeric char", r)
			}
		}
	})

	t.Run("Coverage", func(t *testing.T) {
		alphabet := Alphabet{'a', 'b', 'c'}
		dist := NewRuneDistribution(alphabet)

		seen := make(map[rune]bool)
		for range 1000 {
			r := dist.Draw()
			seen[r] = true
		}

		for _, r := range alphabet {
			if !seen[r] {
				t.Errorf("rune %c not seen after 1000 draws", r)
			}
		}
	})
}

// TestStringsDistribution tests string generation
func TestStringsDistribution(t *testing.T) {
	t.Parallel()

	t.Run("Length", func(t *testing.T) {
		length := 10
		dist := NewStringsDistribution(Alphabetical, length)

		for range 100 {
			s := dist.Draw()
			if len(s) != length {
				t.Errorf("NewStringsDistribution(_, %d).Draw() length = %d, want %d",
					length, len(s), length)
			}
		}
	})

	t.Run("AlphabeticalContent", func(t *testing.T) {
		dist := NewStringsDistribution(Alphabetical, 20)

		s := dist.Draw()
		for i, r := range s {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
				t.Errorf("char at position %d: got %c, want alphabetical", i, r)
			}
		}
	})

	t.Run("NumericalContent", func(t *testing.T) {
		dist := NewStringsDistribution(Numerical, 15)

		s := dist.Draw()
		for i, r := range s {
			if r < '0' || r > '9' {
				t.Errorf("char at position %d: got %c, want digit", i, r)
			}
		}
	})

	t.Run("ZeroLength", func(t *testing.T) {
		dist := NewStringsDistribution(Alphabetical, 0)

		s := dist.Draw()
		if s != "" {
			t.Errorf("NewStringsDistribution(_, 0).Draw() = %q, want empty string", s)
		}
	})
}

// TestBytesDistribution tests byte slice generation
func TestBytesDistribution(t *testing.T) {
	t.Parallel()

	t.Run("Length", func(t *testing.T) {
		length := 32
		dist := NewBytesDistribution(length, rand.Reader)

		for range 100 {
			b := dist.Draw()
			if len(b) != length {
				t.Errorf("NewBytesDistribution(%d, _).Draw() length = %d, want %d",
					length, len(b), length)
			}
		}
	})

	t.Run("Randomness", func(t *testing.T) {
		// Test that we get different byte slices
		dist := NewBytesDistribution(16, rand.Reader)

		b1 := dist.Draw()
		b2 := dist.Draw()

		allSame := true
		for i := range b1 {
			if b1[i] != b2[i] {
				allSame = false
				break
			}
		}

		if allSame {
			t.Errorf("NewBytesDistribution generated identical byte slices")
		}
	})

	t.Run("ZeroLength", func(t *testing.T) {
		dist := NewBytesDistribution(0, rand.Reader)

		b := dist.Draw()
		if len(b) != 0 {
			t.Errorf("NewBytesDistribution(0, _).Draw() length = %d, want 0", len(b))
		}
	})
}
