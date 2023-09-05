package fuzz

import (
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
)

var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func Fuzz_Test(f *testing.F) {
	f.Fuzz(func(t *testing.T, hashIndex uint, message []byte) {
		h := allHashes[int(hashIndex)%len(allHashes)]
		commitment, witness, err := commitments.Commit(h, message)
		require.NoError(t, err)
		err = commitments.Open(h, message, commitment, witness)
		require.NoError(t, err)
	})
}
