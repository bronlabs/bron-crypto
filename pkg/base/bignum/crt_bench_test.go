package bignum_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignum"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func Benchmark_Exp(b *testing.B) {
	prng := crand.Reader
	pBig, err := crand.Prime(prng, 1024)
	require.NoError(b, err)
	p := new(saferith.Nat).SetBig(pBig, 1024)

	qBig, err := crand.Prime(prng, 1024)
	require.NoError(b, err)
	q := new(saferith.Nat).SetBig(qBig, 1024)
	if b, _, _ := p.Cmp(q); b == 1 {
		p, q = q, p
	}
	secretKey, err := paillier.NewSecretKey(p, q)
	require.NoError(b, err)

	n := 128

	// sanity check
	bb, ee := genTestData(b, secretKey, 1, prng)
	r0 := new(saferith.Nat).Exp(bb[0], ee, secretKey.GetNModulus())
	r1 := bignum.FastExp(bb[0], ee, secretKey.N)
	r2 := bignum.FastExpCrt(secretKey.GetCrtNParams(), bb[0], ee, secretKey.GetNModulus())
	r3 := bignum.FastFixedExponentMultiExp(bb, ee, secretKey.N)
	r4 := bignum.FastFixedExponentMultiExpCrt(secretKey.GetCrtNParams(), bb, ee, secretKey.N)
	require.True(b, r0.Eq(r1) == 1)
	require.True(b, r1.Eq(r2) == 1)
	require.True(b, r2.Eq(r3[0]) == 1)
	require.True(b, r3[0].Eq(r4[0]) == 1)

	b.ResetTimer()
	b.Run("saferith", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bases, exp := genTestData(b, secretKey, n, prng)
			for k := 0; k < n; k++ {
				_ = new(saferith.Nat).Exp(bases[i], exp, secretKey.GetNModulus())
			}
		}
	})

	b.Run("BoringSSL", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bases, exp := genTestData(b, secretKey, n, prng)
			for k := 0; k < n; k++ {
				_ = bignum.FastExp(bases[i], exp, secretKey.N)
			}
		}
	})

	b.Run("BoringSSL CRT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bases, exp := genTestData(b, secretKey, n, prng)
			for k := 0; k < n; k++ {
				_ = bignum.FastExpCrt(secretKey.GetCrtNParams(), bases[i], exp, secretKey.GetNModulus())
			}
		}
	})

	b.Run("BoringSSL Parallel", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bases, exp := genTestData(b, secretKey, n, prng)
			_ = bignum.FastFixedExponentMultiExp(bases, exp, secretKey.N)
		}
	})

	b.Run("BoringSSL CRT Parallel", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bases, exp := genTestData(b, secretKey, n, prng)
			_ = bignum.FastFixedExponentMultiExpCrt(secretKey.GetCrtNParams(), bases, exp, secretKey.N)
		}
	})
}

func genTestData(t require.TestingT, secretKey *paillier.SecretKey, n int, prng io.Reader) (bases []*saferith.Nat, exponent *saferith.Nat) {
	exponentBig, err := crand.Int(prng, secretKey.N.Big())
	require.NoError(t, err)
	exponent = new(saferith.Nat).SetBig(exponentBig, secretKey.N.AnnouncedLen())

	bases = make([]*saferith.Nat, n)
	for i := range bases {
		baseBig, err := crand.Int(prng, secretKey.N.Big())
		require.NoError(t, err)
		bases[i] = new(saferith.Nat).SetBig(baseBig, secretKey.N.AnnouncedLen())
	}

	return bases, exponent
}
