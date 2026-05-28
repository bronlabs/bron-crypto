package nt_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

func Benchmark_GeneratePrime(b *testing.B) {
	for _, bits := range []uint{64, 256, 512, 1024} {
		b.Run(fmt.Sprintf("%d-bit", bits), func(b *testing.B) {
			for b.Loop() {
				_, err := nt.GeneratePrime(num.NPlus(), bits, crand.Reader)
				require.NoError(b, err)
			}
		})
	}
}

func Benchmark_GenerateBlumPrime(b *testing.B) {
	for _, bits := range []uint{64, 256, 512, 1024} {
		b.Run(fmt.Sprintf("%d-bit", bits), func(b *testing.B) {
			for b.Loop() {
				_, err := nt.GenerateBlumPrime(num.NPlus(), bits, crand.Reader)
				require.NoError(b, err)
			}
		})
	}
}

func Benchmark_GenerateSafePrime(b *testing.B) {
	for _, bits := range []uint{128, 512, 1024} {
		b.Run(fmt.Sprintf("%d-bit", bits), func(b *testing.B) {
			for b.Loop() {
				_, err := nt.GenerateSafePrime(num.NPlus(), bits, crand.Reader)
				require.NoError(b, err)
			}
		})
	}
}

func Benchmark_GenerateSafePrimePair(b *testing.B) {
	for _, bits := range []uint{256, 1024, 2048} {
		b.Run(fmt.Sprintf("%d-bit", bits), func(b *testing.B) {
			for b.Loop() {
				_, _, err := nt.GenerateSafePrimePair(num.NPlus(), bits, crand.Reader)
				require.NoError(b, err)
			}
		})
	}
}
