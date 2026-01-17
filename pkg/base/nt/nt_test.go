package nt //nolint:testpackage // to access unexported identifiers

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func TestMillerRabinChecks(t *testing.T) {
	t.Parallel()

	t.Run("Exact match", func(t *testing.T) {
		t.Parallel()
		keySize := uint(2048)
		expected := millerRabinIterations[keySize]
		actual := MillerRabinChecks(keySize)
		require.Equal(t, expected, actual)
	})

	t.Run("Between entries", func(t *testing.T) {
		t.Parallel()
		keySize := uint(3072) // Between 2048 and 4096
		expected := millerRabinIterations[2048]
		actual := MillerRabinChecks(keySize)
		require.Equal(t, expected, actual)
	})

	t.Run("Below minimum", func(t *testing.T) {
		t.Parallel()
		keySize := uint(50) // Below the smallest entry (64)
		expected := max(
			base.StatisticalSecurityBits/4,
			millerRabinIterations[64],
		)
		actual := MillerRabinChecks(keySize)
		require.Equal(t, expected, actual)
	})
}

func TestGenerateSafePrime(t *testing.T) {
	t.Parallel()
	bitSize := uint(128) // this is to keep the test reliably fast
	prime, err := GenerateSafePrime(num.N(), bitSize)
	require.NoError(t, err)
	require.True(t, prime.IsProbablyPrime())
	pMinus1, err := prime.TrySub(num.N().One())
	require.NoError(t, err)
	halfPMinus1, err := pMinus1.TryDiv(num.N().FromUint64(2))
	require.NoError(t, err)
	require.True(t, halfPMinus1.IsProbablyPrime())
}

func TestGenerateSafePrimePair(t *testing.T) {
	t.Parallel()
	bitSize := uint(128) // this is to keep the test reliably fast
	p, q, err := GenerateSafePrimePair(num.N(), bitSize)
	require.NoError(t, err)

	require.True(t, p.IsProbablyPrime())
	pMinus1, err := p.TrySub(num.N().One())
	require.NoError(t, err)
	halfPMinus1, err := pMinus1.TryDiv(num.N().FromUint64(2))
	require.NoError(t, err)
	require.True(t, halfPMinus1.IsProbablyPrime())

	require.True(t, q.IsProbablyPrime())
	qMinus1, err := q.TrySub(num.N().One())
	require.NoError(t, err)
	halfQMinus1, err := qMinus1.TryDiv(num.N().FromUint64(2))
	require.NoError(t, err)
	require.True(t, halfQMinus1.IsProbablyPrime())
}

func TestGeneratePrimePair(t *testing.T) {
	t.Parallel()
	bitSize := uint(2048)
	p, q, err := GeneratePrimePair(num.N(), bitSize, pcg.NewRandomised())
	require.NoError(t, err)

	require.True(t, p.IsProbablyPrime())
	require.True(t, q.IsProbablyPrime())
}
