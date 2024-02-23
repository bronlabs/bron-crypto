package fuzz

import (
	crand "crypto/rand"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/commitments"
)

var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func Fuzz_Test(f *testing.F) {
	f.Fuzz(func(t *testing.T, hashIndex uint, message []byte) {
		commitments.CommitmentHashFunction = allHashes[int(hashIndex)%len(allHashes)]
		commitment, witness, err := commitments.CommitWithoutSession(crand.Reader, message)
		require.NoError(t, err)
		err = commitments.OpenWithoutSession(commitment, witness, message)
		require.NoError(t, err)
	})
}
