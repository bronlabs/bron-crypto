package hagrid_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestNilTranscriptHandling(t *testing.T) {
	t.Parallel()

	var tape transcripts.Transcript

	transcripts.Append[*k256.Scalar](tape, "label")

	_, err := transcripts.Extract[*k256.Scalar](tape, "label", k256.NewScalarField())
	require.Error(t, err)
}

func TestCloneIndependence(t *testing.T) {
	t.Parallel()

	tape := hagrid.NewTranscript("test")
	tape.AppendDomainSeparator("domain")
	tape.AppendBytes("label", []byte("a"))

	cloned := tape.Clone()
	require.NotNil(t, cloned)

	originalBefore, err := tape.ExtractBytes("challenge", 32)
	require.NoError(t, err)
	clonedBefore, err := cloned.ExtractBytes("challenge", 32)
	require.NoError(t, err)
	require.Equal(t, originalBefore, clonedBefore)

	tape.AppendBytes("label", []byte("b"))
	originalAfter, err := tape.ExtractBytes("challenge", 32)
	require.NoError(t, err)
	clonedAfter, err := cloned.ExtractBytes("challenge", 32)
	require.NoError(t, err)
	require.NotEqual(t, originalAfter, clonedAfter)
}

func TestExtractRejectsNilStructure(t *testing.T) {
	t.Parallel()

	tape := hagrid.NewTranscript("test")
	_, err := transcripts.Extract[*k256.Scalar](tape, "label", nil)
	require.Error(t, err)
}
