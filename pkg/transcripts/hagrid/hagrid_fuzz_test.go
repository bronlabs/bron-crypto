package hagrid_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func FuzzHagrid(f *testing.F) {
	f.Fuzz(func(t *testing.T, label []byte, message []byte, l uint) {
		mt := hagrid.NewTranscript(string(label), nil)
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
