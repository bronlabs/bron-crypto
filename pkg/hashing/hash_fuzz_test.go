package hashing_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/hashing/tmmohash"
)

func FuzzHashPrefixedLength(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		_, err := hashing.HashPrefixedLength(sha256.New, a)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

func FuzzTmmo(f *testing.F) {
	f.Fuzz(func(t *testing.T, input []byte, iv []byte, length int) {
		h, err := tmmohash.NewTmmoHash(length, 64, iv)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		_, err = h.Write(input)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		_ = h.Sum(nil)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}
