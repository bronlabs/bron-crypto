package fuzz

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/hashing"
)

func Fuzz_Test_hash(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		_, err := hashing.FiatShamirHKDF(sha256.New, a)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

func Fuzz_Test_hashaes(f *testing.F) {
	f.Fuzz(func(t *testing.T, input []byte, iv []byte, length int) {
		h, err := hashing.NewAesHash(length, iv)
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
