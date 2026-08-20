package primegen //nolint:testpackage // to access unexported identifiers

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func testRoundsFor(bits uint) Rounds {
	// Generous fixed counts are fine for tests; production counts come from
	// nt.MillerRabinChecks.
	_ = bits
	return Rounds{Q: 40, Half: 40}
}

func TestGenerate_Classes(t *testing.T) {
	t.Parallel()

	const bits = 64
	four := big.NewInt(4)

	for name, class := range map[string]Class{"plain": Plain, "blum": Blum, "safe": Safe} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			q, err := Generate(class, bits, nil, testRoundsFor(bits), pcg.NewRandomised())
			require.NoError(t, err)
			require.Equal(t, bits, q.BitLen())
			require.True(t, q.ProbablyPrime(40))
			require.Equal(t, uint(1), q.Bit(0))
			if class == Blum || class == Safe {
				require.Equal(t, int64(3), new(big.Int).Mod(q, four).Int64())
			}
			if class == Safe {
				half := new(big.Int).Rsh(q, 1)
				require.True(t, half.ProbablyPrime(40))
			}
		})
	}
}

func TestGenerate_LowerBound(t *testing.T) {
	t.Parallel()

	const bits = 64
	// ⌈√(2^127)⌉ — the FIPS 186-5 A.1.1 2(b) bound for a 128-bit modulus.
	x := new(big.Int).Lsh(big.NewInt(1), 2*bits-1)
	lo := new(big.Int).Sqrt(x)
	if new(big.Int).Mul(lo, lo).Cmp(x) < 0 {
		lo.Add(lo, big.NewInt(1))
	}
	for range 8 {
		q, err := Generate(Plain, bits, lo, testRoundsFor(bits), pcg.NewRandomised())
		require.NoError(t, err)
		require.Equal(t, bits, q.BitLen())
		require.GreaterOrEqual(t, q.Cmp(lo), 0)
	}
}

func TestGeneratePair(t *testing.T) {
	t.Parallel()

	// 128-bit primes exercise the |p−q| distance branch (bits > 100).
	const bits = 128
	x := new(big.Int).Lsh(big.NewInt(1), 2*bits-1)
	lo := new(big.Int).Sqrt(x)
	if new(big.Int).Mul(lo, lo).Cmp(x) < 0 {
		lo.Add(lo, big.NewInt(1))
	}
	p, q, err := GeneratePair(Plain, bits, lo, testRoundsFor(bits), pcg.NewRandomised())
	require.NoError(t, err)
	require.NotEqual(t, 0, p.Cmp(q))
	for _, prime := range []*big.Int{p, q} {
		require.Equal(t, bits, prime.BitLen())
		require.True(t, prime.ProbablyPrime(40))
		require.GreaterOrEqual(t, prime.Cmp(lo), 0)
	}
	// FIPS 186-5 A.1.1 2(d).
	diff := new(big.Int).Sub(p, q)
	require.Greater(t, diff.BitLen(), bits-100)
	// The lower bound makes the modulus bit length exact.
	require.Equal(t, 2*bits, new(big.Int).Mul(p, q).BitLen())
	// gcd(N, φ(N)) = 1 — Paillier / Π^mod precondition, enforced by the
	// pair collector (and automatic for equal-length primes).
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	require.Equal(t, 0, new(big.Int).GCD(nil, nil, n, phi).Cmp(big.NewInt(1)))
}

// TestGenerate_SafeCoversQuadraticResidues checks that the safe-prime
// generator's output reaches residue classes that are quadratic residues
// modulo the sieve primes. The retired Joye-Paillier generator could never
// produce such primes (audit finding TOB-BLCG-4); under the uniform
// generator the probability that all samples below are QNR modulo every
// sieve prime is ≈ 0.065^64 < 10^-75.
func TestGenerate_SafeCoversQuadraticResidues(t *testing.T) {
	t.Parallel()

	const bits = 32
	const samples = 64
	params, err := paramsFor(Safe, bits)
	require.NoError(t, err)

	seenQR := false
	for range samples {
		q, err := Generate(Safe, bits, nil, testRoundsFor(bits), pcg.NewRandomised())
		require.NoError(t, err)
		for i := range params.nPi {
			p := big.NewInt(smallPrimes[i])
			// Any safe prime avoids residues 0 and 1 mod every sieve prime.
			require.Greater(t, new(big.Int).Mod(q, p).Int64(), int64(1))
			if big.Jacobi(q, p) == 1 {
				seenQR = true
			}
		}
	}
	require.True(t, seenQR, "no quadratic-residue class was ever hit: output looks QNR-restricted like Joye-Paillier")
}

// TestGenerate_PlainCoversResidueOne checks that plain primes reach residue
// 1 modulo sieve primes — the class forbidden for safe primes but perfectly
// admissible for plain ones. The probability that 48 uniform samples all
// miss residue 1 at every sieve prime is ≈ 0.24^48 < 10^-29.
func TestGenerate_PlainCoversResidueOne(t *testing.T) {
	t.Parallel()

	const bits = 32
	const samples = 48
	params, err := paramsFor(Plain, bits)
	require.NoError(t, err)

	seenOne := false
	for range samples {
		q, err := Generate(Plain, bits, nil, testRoundsFor(bits), pcg.NewRandomised())
		require.NoError(t, err)
		for i := range params.nPi {
			p := big.NewInt(smallPrimes[i])
			residue := new(big.Int).Mod(q, p).Int64()
			require.Positive(t, residue)
			if residue == 1 {
				seenOne = true
			}
		}
	}
	require.True(t, seenOne, "residue 1 was never hit: plain primes look over-restricted")
}

func TestGenerate_Invalid(t *testing.T) {
	t.Parallel()

	rounds := testRoundsFor(64)
	_, err := Generate(Plain, 64, nil, rounds, nil)
	require.Error(t, err)
	_, err = Generate(Plain, MinBits-1, nil, rounds, pcg.NewRandomised())
	require.Error(t, err)
	_, err = Generate(Plain, 64, nil, Rounds{Q: 0}, pcg.NewRandomised())
	require.Error(t, err)
	_, err = Generate(Safe, 64, nil, Rounds{Q: 40, Half: 0}, pcg.NewRandomised())
	require.Error(t, err)
	_, err = Generate(Plain, 64, big.NewInt(3), rounds, pcg.NewRandomised()) // lo of the wrong bit length
	require.Error(t, err)
}
