package nt //nolint:testpackage // to access unexported identifiers

import (
	"math/big"
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

func TestPrimeGenerator_Regular(t *testing.T) {
	t.Parallel()
	// bits >= 512 is required because the regular path internally calls
	// rsa.GenerateKey(2*bits), which rejects keys smaller than 1024 bits.
	gen, err := NewPrimeGenerator(num.N(), false, false)
	require.NoError(t, err)
	prime, err := gen.Generate(512, pcg.NewRandomised())
	require.NoError(t, err)
	require.True(t, prime.IsProbablyPrime())
}

func TestPrimeGenerator_Safe(t *testing.T) {
	t.Parallel()
	gen, err := NewPrimeGenerator(num.N(), true, false)
	require.NoError(t, err)
	prime, err := gen.Generate(128, pcg.NewRandomised())
	require.NoError(t, err)
	require.True(t, prime.IsProbablyPrime())
	sophieGermain := new(big.Int).Rsh(prime.Big(), 1)
	require.True(t, sophieGermain.ProbablyPrime(40))
}

func TestPrimeGenerator_Blum(t *testing.T) {
	t.Parallel()
	four, err := num.NPlus().FromUint64(4)
	require.NoError(t, err)

	gen, err := NewPrimeGenerator(num.N(), false, true)
	require.NoError(t, err)
	prime, err := gen.Generate(128, pcg.NewRandomised())
	require.NoError(t, err)
	require.True(t, prime.IsProbablyPrime())
	require.Equal(t, uint64(3), prime.Mod(four).Nat().Uint64())
}

func TestPrimeGenerator_SafeBlum(t *testing.T) {
	t.Parallel()
	four, err := num.NPlus().FromUint64(4)
	require.NoError(t, err)

	gen, err := NewPrimeGenerator(num.N(), true, true)
	require.NoError(t, err)
	prime, err := gen.Generate(128, pcg.NewRandomised())
	require.NoError(t, err)
	require.True(t, prime.IsProbablyPrime())
	require.Equal(t, uint64(3), prime.Mod(four).Nat().Uint64())
	sophieGermain := new(big.Int).Rsh(prime.Big(), 1)
	require.True(t, sophieGermain.ProbablyPrime(40))
}

func TestPrimePairGenerator_Regular(t *testing.T) {
	t.Parallel()
	gen, err := NewPrimePairGenerator(num.N(), false, false)
	require.NoError(t, err)
	p, q, err := gen.Generate(2048, pcg.NewRandomised())
	require.NoError(t, err)
	require.False(t, p.Equal(q))
	require.True(t, p.IsProbablyPrime())
	require.True(t, q.IsProbablyPrime())
}

func TestPrimePairGenerator_Safe(t *testing.T) {
	t.Parallel()
	gen, err := NewPrimePairGenerator(num.N(), true, false)
	require.NoError(t, err)
	p, q, err := gen.Generate(256, pcg.NewRandomised())
	require.NoError(t, err)
	require.False(t, p.Equal(q))
	require.True(t, p.IsProbablyPrime())
	require.True(t, q.IsProbablyPrime())
	sgP := new(big.Int).Rsh(p.Big(), 1)
	require.True(t, sgP.ProbablyPrime(40))
	sgQ := new(big.Int).Rsh(q.Big(), 1)
	require.True(t, sgQ.ProbablyPrime(40))
}

func TestPrimePairGenerator_PaillierBlum(t *testing.T) {
	t.Parallel()
	keyLen := uint(256) // this is to keep the test reliably fast
	four, err := num.NPlus().FromUint64(4)
	require.NoError(t, err)

	gen, err := NewPrimePairGenerator(num.NPlus(), false, true)
	require.NoError(t, err)
	p, q, err := gen.Generate(keyLen, pcg.NewRandomised())
	require.NoError(t, err)
	require.False(t, p.Equal(q))

	require.True(t, p.IsProbablyPrime())
	require.Equal(t, uint64(3), p.Mod(four).Nat().Uint64())

	require.True(t, q.IsProbablyPrime())
	require.Equal(t, uint64(3), q.Mod(four).Nat().Uint64())

	N := p.Mul(q)
	require.Equal(t, int(keyLen), N.AnnouncedLen())

	phiN := p.Lift().Decrement().Mul(q.Lift().Decrement())
	require.True(t, phiN.Abs().Coprime(N.Nat()))
}

func TestPrimePairGenerator_SafePaillierBlum(t *testing.T) {
	t.Parallel()
	keyLen := uint(256)
	four, err := num.NPlus().FromUint64(4)
	require.NoError(t, err)

	gen, err := NewPrimePairGenerator(num.NPlus(), true, true)
	require.NoError(t, err)
	p, q, err := gen.Generate(keyLen, pcg.NewRandomised())
	require.NoError(t, err)
	require.False(t, p.Equal(q))

	require.True(t, p.IsProbablyPrime())
	require.Equal(t, uint64(3), p.Mod(four).Nat().Uint64())
	sgP := new(big.Int).Rsh(p.Big(), 1)
	require.True(t, sgP.ProbablyPrime(40))

	require.True(t, q.IsProbablyPrime())
	require.Equal(t, uint64(3), q.Mod(four).Nat().Uint64())
	sgQ := new(big.Int).Rsh(q.Big(), 1)
	require.True(t, sgQ.ProbablyPrime(40))

	N := p.Mul(q)
	require.Equal(t, int(keyLen), N.AnnouncedLen())

	phiN := p.Lift().Decrement().Mul(q.Lift().Decrement())
	require.True(t, phiN.Abs().Coprime(N.Nat()))
}
