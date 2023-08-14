package noninteractive_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	integration_test_utils "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/signing/noninteractive/test_utils"
)

func Test_PreGenHappyPath(t *testing.T) {
	t.Parallel()

	curve := k256.New()
	hashFunc := sha256.New
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hashFunc,
	}
	threshold := 2
	n := 3
	sid := []byte("sessionId")
	tau := 64
	transcriptAppLabel := "Lindell2017PreGenTest"

	identities, err := integration_test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohort, err := integration_test_utils.MakeCohort(cipherSuite, protocols.LINDELL17, identities, threshold, identities)
	require.NoError(t, err)

	transcripts := integration_test_utils.MakeTranscripts(transcriptAppLabel, identities)
	participants, err := test_utils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
	require.NoError(t, err)

	batches, err := test_utils.DoLindell2017PreGen(participants)
	require.NoError(t, err)
	require.NotNil(t, batches)

	t.Run("R is the same in each batch", func(t *testing.T) {
		t.Parallel()

		for i := 0; i < tau; i++ {
			for p1 := 0; p1 < len(participants); p1++ {
				for p2 := p1 + 1; p2 < len(participants); p2++ {
					l := batches[p1].PreSignatures[i].BigR[participants[p2].GetIdentityKey().Hash()]
					r := batches[p2].PreSignatures[i].BigR[participants[p1].GetIdentityKey().Hash()]
					require.True(t, l.Equal(r))
				}
			}
		}
	})

	t.Run("transcripts recoded the same data", func(t *testing.T) {
		t.Parallel()
		ok := integration_test_utils.TranscriptAtSameState("gimme", transcripts)
		require.True(t, ok)
	})
}
