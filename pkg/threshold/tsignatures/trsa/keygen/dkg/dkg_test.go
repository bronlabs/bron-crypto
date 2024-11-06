package dkg_test

import (
	"crypto"
	crand "crypto/rand"
	nativeRsa "crypto/rsa"
	"crypto/sha256"
	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/rsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/test_utils"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

const (
	// primeBitLen is ridiculously small for tests
	primeBitLen = 256
)

func Test_PartialSignature(t *testing.T) {
	t.Parallel()
	var err error
	prng := crand.Reader
	message := []byte("Hello World")
	padding := rsa.NewPKCS1v15Padding()
	hashFunc := sha256.New

	// Run DKG
	shards, pk := test_utils.RunDistributedKeyGen(t, primeBitLen, prng)

	// partially sign message
	combinations, err := combinatorics.Combinations(shards, 2)
	require.NoError(t, err)
	for _, combination := range combinations {
		partialSignatures := make([]*trsa.PartialSignature, len(combination))
		for i, shard := range combination {
			partialSignatures[i], err = shard.SignPartially(padding, hashFunc, message)
			require.NoError(t, err)
		}

		// aggregate
		signature, err := trsa.Aggregate(pk, partialSignatures...)
		require.NoError(t, err)

		// verify against native RSA
		digest := sha256.Sum256(message)
		err = nativeRsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], signature[:])
		require.NoError(t, err)
	}
}

func Test_DKG(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	// run DKG
	shards, pk := test_utils.RunDistributedKeyGen(t, primeBitLen, prng)

	t.Run("public keys match and have correct sizes", func(t *testing.T) {
		t.Parallel()
		require.Zero(t, pk.N.Cmp(shards[0].N))
		require.Zero(t, pk.N.Cmp(shards[1].N))
		require.Zero(t, pk.N.Cmp(shards[2].N))
		require.Equal(t, pk.E, shards[0].E)
		require.Equal(t, pk.E, shards[1].E)
		require.Equal(t, pk.E, shards[2].E)

		require.Equal(t, 2*primeBitLen, pk.N.BitLen())
	})

	t.Run("private key shares match public key and have correct size", func(t *testing.T) {
		t.Parallel()
		dealer, err := replicated.NewIntDealer(2, 3, replicated.BitLen(primeBitLen))
		require.NoError(t, err)

		p, err := dealer.Reveal(shards[0].PShare, shards[1].PShare, shards[2].PShare)
		require.NoError(t, err)
		require.Equal(t, primeBitLen, p.BitLen())
		require.Equal(t, uint(1), p.Bit(1))
		require.True(t, p.ProbablyPrime(2))

		q, err := dealer.Reveal(shards[0].QShare, shards[1].QShare, shards[2].QShare)
		require.NoError(t, err)
		require.Equal(t, primeBitLen, q.BitLen())
		require.Equal(t, uint(1), q.Bit(1))
		require.True(t, q.ProbablyPrime(2))

		pq := new(big.Int).Mul(p, q)
		require.Zero(t, pk.N.Cmp(pq))

		pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
		qMinusOne := new(big.Int).Sub(q, big.NewInt(1))
		phi := new(big.Int).Mul(pMinusOne, qMinusOne)

		d, err := dealer.Reveal(shards[0].DShare, shards[1].DShare, shards[2].DShare)
		require.NoError(t, err)

		dTimesE := new(big.Int).Mul(d, big.NewInt(int64(pk.E)))
		dTimesE.Mod(dTimesE, phi)
		require.Zero(t, dTimesE.Cmp(big.NewInt(1)))
	})
}
