package ct_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func BenchmarkConstantTime(b *testing.B) {
	b.Run("IsZero", func(b *testing.B) {
		var result ct.Choice
		for range b.N {
			result = ct.IsZero(uint64(b.N))
		}
		_ = result
	})

	b.Run("Equal", func(b *testing.B) {
		var result ct.Choice
		for range b.N {
			result = ct.Equal(uint64(b.N), uint64(b.N+1))
		}
		_ = result
	})

	b.Run("SelectInteger", func(b *testing.B) {
		var result uint64
		for range b.N {
			result = ct.CSelectInt(ct.Choice(b.N&1), uint64(b.N), uint64(b.N+1))
		}
		_ = result
	})

	b.Run("Isqrt64", func(b *testing.B) {
		var result uint64
		for range b.N {
			result = ct.Isqrt64(uint64(b.N))
		}
		_ = result
	})

	b.Run("BytesCompare", func(b *testing.B) {
		x := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		y := []byte{1, 2, 3, 4, 5, 6, 7, 9}
		var lt, eq, gt ct.Bool
		for range b.N {
			lt, eq, gt = ct.CompareBytes(x, y)
		}
		_ = lt
		_ = eq
		_ = gt
	})
}
