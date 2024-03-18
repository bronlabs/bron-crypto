package uint256_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/uints/uint256"
	"io"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
)

func Benchmark_Add(b *testing.B) {
	// make some samples
	nSamples := 4096
	samplesU256 := make([]uint256.U256, nSamples)
	samplesSaferith := make([]saferith.Nat, nSamples)
	for i := range samplesU256 {
		sample := make([]byte, 32)
		_, err := io.ReadFull(crand.Reader, sample)
		require.NoError(b, err)
		samplesU256[i] = uint256.NewFromBytesLE(sample)
		samplesSaferith[i].SetBytes(bitstring.ReverseBytes(sample))
	}

	b.Run("u256", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhs := samplesU256[i%nSamples]
			rhs := samplesU256[(i*(nSamples+1))%nSamples]

			_ = lhs.Add(rhs)
		}
	})

	b.Run("saferith", func(b *testing.B) {
		var result saferith.Nat
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhs := samplesSaferith[i%nSamples]
			rhs := samplesSaferith[(i*(nSamples+1))%nSamples]

			_ = result.Add(&lhs, &rhs, 256)
		}
	})
}

func Benchmark_Sub(b *testing.B) {
	// make some samples
	nSamples := 4096
	samplesU256 := make([]uint256.U256, nSamples)
	samplesSaferith := make([]saferith.Nat, nSamples)
	for i := range samplesU256 {
		sample := make([]byte, 32)
		_, err := io.ReadFull(crand.Reader, sample)
		require.NoError(b, err)
		samplesU256[i] = uint256.NewFromBytesLE(sample)
		samplesSaferith[i].SetBytes(bitstring.ReverseBytes(sample))
	}

	b.Run("u256", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhs := samplesU256[i%nSamples]
			rhs := samplesU256[(i*(nSamples+1))%nSamples]

			_ = lhs.Sub(rhs)
		}
	})

	b.Run("saferith", func(b *testing.B) {
		var result saferith.Nat
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhs := samplesSaferith[i%nSamples]
			rhs := samplesSaferith[(i*(nSamples+1))%nSamples]

			_ = result.Sub(&lhs, &rhs, 256)
		}
	})
}

func Benchmark_Mul(b *testing.B) {
	// make some samples
	nSamples := 4096
	samplesU256 := make([]uint256.U256, nSamples)
	samplesSaferith := make([]saferith.Nat, nSamples)
	for i := range samplesU256 {
		sample := make([]byte, 32)
		_, err := io.ReadFull(crand.Reader, sample)
		require.NoError(b, err)
		samplesU256[i] = uint256.NewFromBytesLE(sample)
		samplesSaferith[i].SetBytes(bitstring.ReverseBytes(sample))
	}

	b.Run("u256", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhs := samplesU256[i%nSamples]
			rhs := samplesU256[(i*(nSamples+1))%nSamples]

			_ = lhs.Mul(rhs)
		}
	})

	b.Run("saferith", func(b *testing.B) {
		var result saferith.Nat
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhs := samplesSaferith[i%nSamples]
			rhs := samplesSaferith[(i*(nSamples+1))%nSamples]

			_ = result.Mul(&lhs, &rhs, 256)
		}
	})
}
