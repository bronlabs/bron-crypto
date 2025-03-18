package impl_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves2/k256/impl"
)

func Benchmark_K256(b *testing.B) {
	prng := crand.Reader

	b.Run("fp", func(b *testing.B) {
		var x, y impl.Fp
		ok := x.SetRandom(prng)
		require.True(b, ok == 1)
		ok = y.SetRandom(prng)
		require.True(b, ok == 1)

		b.Run("add", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				x.Add(&x, &y)
			}
		})

		b.Run("mul", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				x.Mul(&x, &y)
			}
		})

		b.Run("square", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				x.Square(&x)
			}
		})

		b.Run("inv", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = x.Inv(&x)
			}
		})

		b.Run("sqrt", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = y.Sqrt(&y)
			}
		})
	})

	b.Run("fq", func(b *testing.B) {
		var x, y impl.Fq
		ok := x.SetRandom(prng)
		require.True(b, ok == 1)
		ok = y.SetRandom(prng)
		require.True(b, ok == 1)

		b.Run("add", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				x.Add(&x, &y)
			}
		})

		b.Run("mul", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				x.Mul(&x, &y)
			}
		})

		b.Run("square", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				x.Square(&x)
			}
		})

		b.Run("inv", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = x.Inv(&x)
			}
		})

		b.Run("sqrt", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = y.Sqrt(&y)
			}
		})
	})

	b.Run("point", func(b *testing.B) {
		var x, y impl.Point
		ok := x.SetRandom(prng)
		require.True(b, ok == 1)
		ok = y.SetRandom(prng)
		require.True(b, ok == 1)

		b.Run("add", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				x.Add(&x, &y)
			}
		})

		b.Run("double", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				x.Double(&x)
			}
		})
	})
}
