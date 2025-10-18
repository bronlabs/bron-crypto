package ct

import (
	"testing"
)

// BenchmarkSelectComparison compares CSelect vs Select for integer types
func BenchmarkSelectComparison(b *testing.B) {
	// Test with different integer sizes

	b.Run("Select_uint8", func(b *testing.B) {
		var a, x uint8 = 42, 100
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = SelectInteger(choice, a, x)
		}
		_ = a
	})

	b.Run("CSelect_uint8", func(b *testing.B) {
		var a, x uint8 = 42, 100
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = CSelect(choice, a, x)
		}
		_ = a
	})

	b.Run("Select_uint32", func(b *testing.B) {
		var a, x uint32 = 42, 100
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = SelectInteger(choice, a, x)
		}
		_ = a
	})

	b.Run("CSelect_uint32", func(b *testing.B) {
		var a, x uint32 = 42, 100
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = CSelect(choice, a, x)
		}
		_ = a
	})

	b.Run("Select_uint64", func(b *testing.B) {
		var a, x uint64 = 42, 100
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = SelectInteger(choice, a, x)
		}
		_ = a
	})

	b.Run("CSelect_uint64", func(b *testing.B) {
		var a, x uint64 = 42, 100
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = CSelect(choice, a, x)
		}
		_ = a
	})

	b.Run("Select_int64", func(b *testing.B) {
		var a, x int64 = -42, 100
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = SelectInteger(choice, a, x)
		}
		_ = a
	})

	b.Run("CSelect_int64", func(b *testing.B) {
		var a, x int64 = -42, 100
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = CSelect(choice, a, x)
		}
		_ = a
	})
}

// BenchmarkCSelectTypes benchmarks CSelect with various types
func BenchmarkCSelectTypes(b *testing.B) {
	b.Run("small_struct", func(b *testing.B) {
		type Small struct {
			X int
			Y int
		}
		a := Small{1, 2}
		x := Small{3, 4}
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = CSelect(choice, a, x)
		}
		_ = a
	})

	b.Run("large_struct", func(b *testing.B) {
		type Large struct {
			Data [256]byte
			ID   int
		}
		var a, x Large
		a.ID = 1
		x.ID = 2
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = CSelect(choice, a, x)
		}
		_ = a
	})

	b.Run("slice", func(b *testing.B) {
		a := []int{1, 2, 3, 4, 5}
		x := []int{6, 7, 8, 9, 10}
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = CSelect(choice, a, x)
		}
		_ = a
	})

	b.Run("interface", func(b *testing.B) {
		var a, x any = 42, "hello"
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			a = CSelect(choice, a, x)
		}
		_ = a
	})
}

// BenchmarkCMOV benchmarks the CMOV function
func BenchmarkCMOV(b *testing.B) {
	b.Run("uint64", func(b *testing.B) {
		var dst uint64 = 42
		var src uint64 = 100
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			CMOV(&dst, choice, &src)
		}
	})

	b.Run("struct", func(b *testing.B) {
		type TestStruct struct {
			X int
			Y int
		}
		dst := TestStruct{1, 2}
		src := TestStruct{3, 4}
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			CMOV(&dst, choice, &src)
		}
	})

	b.Run("array_256", func(b *testing.B) {
		var dst, src [256]byte
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			CMOV(&dst, choice, &src)
		}
	})
}

// BenchmarkCSwap benchmarks the CSwap function
func BenchmarkCSwap(b *testing.B) {
	b.Run("uint64", func(b *testing.B) {
		var x uint64 = 42
		var y uint64 = 100
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			CSwap(&x, &y, choice)
		}
	})

	b.Run("struct", func(b *testing.B) {
		type TestStruct struct {
			X int
			Y int
		}
		x := TestStruct{1, 2}
		y := TestStruct{3, 4}
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			CSwap(&x, &y, choice)
		}
	})

	b.Run("array_256", func(b *testing.B) {
		var x, y [256]byte
		choice := Choice(1)
		b.ResetTimer()
		for range b.N {
			CSwap(&x, &y, choice)
		}
	})
}
