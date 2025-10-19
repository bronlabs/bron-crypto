package impl_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
)

func Benchmark_Edwards25519(b *testing.B) {
	prng := crand.Reader

	b.Run("fp", func(b *testing.B) {
		var x, y impl.Fp
		ok := x.SetRandom(prng)
		require.True(b, ok == 1)
		ok = y.SetRandom(prng)
		require.True(b, ok == 1)

		b.Run("add", func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				x.Add(&x, &y)
			}
		})

		b.Run("mul", func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				x.Mul(&x, &y)
			}
		})

		b.Run("square", func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				x.Square(&x)
			}
		})

		b.Run("inv", func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				_ = x.Inv(&x)
			}
		})

		b.Run("sqrt", func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
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
			for range b.N {
				x.Add(&x, &y)
			}
		})

		b.Run("mul", func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				x.Mul(&x, &y)
			}
		})

		b.Run("square", func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				x.Square(&x)
			}
		})

		b.Run("inv", func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				_ = x.Inv(&x)
			}
		})

		b.Run("sqrt", func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
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
			for range b.N {
				x.Add(&x, &y)
			}
		})

		b.Run("double", func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				x.Double(&x)
			}
		})
	})
}
