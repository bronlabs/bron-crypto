package fuzz

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

func Fuzz_Test(f *testing.F) {
	f.Fuzz(func(t *testing.T, label []byte, message []byte, l int) {
		mt := hagrid.NewTranscript(string(label))
		mt.AppendMessages(string(label), message)
		_, err := mt.ExtractBytes(string(label), l)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
	})
}
