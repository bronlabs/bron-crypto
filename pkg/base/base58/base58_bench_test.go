package base58_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/base58"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func benchmarkEncode(b *testing.B, size int) {
	b.Helper()
	data := make([]byte, size)
	_, err := io.ReadFull(pcg.NewRandomised(), data)
	require.NoError(b, err)
	for range b.N {
		base58.Encode(data)
	}
}

func benchmarkCheckEncode(b *testing.B, size int) {
	b.Helper()
	data := make([]byte, size)
	_, err := io.ReadFull(pcg.NewRandomised(), data)
	require.NoError(b, err)
	var version base58.VersionPrefix = 0x00
	for range b.N {
		base58.CheckEncode(data, version)
	}
}

func benchmarkDecode(b *testing.B, size int) {
	b.Helper()
	data := make([]byte, size)
	_, err := io.ReadFull(pcg.NewRandomised(), data)
	require.NoError(b, err)
	encoded := base58.Encode(data)
	b.ResetTimer()
	for range b.N {
		base58.Decode(encoded)
	}
}

func benchmarkCheckDecode(b *testing.B, size int) {
	b.Helper()
	data := make([]byte, size)
	_, err := io.ReadFull(pcg.NewRandomised(), data)
	require.NoError(b, err)
	var version base58.VersionPrefix = 0x00
	encoded := base58.CheckEncode(data, version)
	b.ResetTimer()
	for range b.N {
		_, _, err := base58.CheckDecode(encoded)
		require.NoError(b, err)
	}
}

func BenchmarkEncode32(b *testing.B) {
	benchmarkEncode(b, 32)
}

func BenchmarkEncode256(b *testing.B) {
	benchmarkEncode(b, 256)
}

func BenchmarkDecode32(b *testing.B) {
	benchmarkDecode(b, 32)
}

func BenchmarkDecode256(b *testing.B) {
	benchmarkDecode(b, 256)
}

func BenchmarkCheckEncode32(b *testing.B) {
	benchmarkCheckEncode(b, 32)
}

func BenchmarkCheckEncode256(b *testing.B) {
	benchmarkCheckEncode(b, 256)
}

func BenchmarkCheckDecode32(b *testing.B) {
	benchmarkCheckDecode(b, 32)
}

func BenchmarkCheckDecode256(b *testing.B) {
	benchmarkCheckDecode(b, 256)
}
