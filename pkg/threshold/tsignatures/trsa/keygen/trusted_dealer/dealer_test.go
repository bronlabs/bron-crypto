package trusted_dealer_test

import (
	"crypto"
	crand "crypto/rand"
	nativeRsa "crypto/rsa"
	"crypto/sha256"
	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/rsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/trusted_dealer"
	"github.com/stretchr/testify/require"
	"maps"
	"slices"
	"testing"
)

var accessStructures = []struct{ th, n uint }{
	{th: 2, n: 3},
	{th: 4, n: 5},
	{th: 5, n: 6},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	const primeBitLen = 2048
	prng := crand.Reader
	message := []byte("Hello World")
	padding := rsa.NewPKCS1v15Padding()
	hashFunc := sha256.New

	for _, as := range accessStructures {
		// deal shards
		shards, pk, err := trusted_dealer.Deal(primeBitLen, as.th, as.n, prng)
		require.NoError(t, err)

		// partially sign message
		shardsSlice := slices.Collect(maps.Values(shards))
		combinations, err := combinatorics.Combinations(shardsSlice, as.th)
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
}
