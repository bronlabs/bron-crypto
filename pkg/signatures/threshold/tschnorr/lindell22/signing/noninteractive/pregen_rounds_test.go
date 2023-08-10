package noninteractive_test

import (
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	integration_test_utils "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing/noninteractive/test_utils"
)

func Test_PreGenHappyPath(t *testing.T) {
	t.Parallel()

	curve := curves.ED25519()
	hashFunc := sha512.New
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hashFunc,
	}
	threshold := 3
	n := 5
	sid := []byte("sessionId")
	tau := 64
	transcriptAppLabel := "Lindell2022PreGenTest"

	identities, err := integration_test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohort, err := integration_test_utils.MakeCohort(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
	require.NoError(t, err)

	transcripts := integration_test_utils.MakeTranscripts(transcriptAppLabel, identities)
	participants, err := test_utils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
	require.NoError(t, err)

	batches, err := test_utils.DoLindell2022PreGen(participants)
	require.NoError(t, err)
	require.NotNil(t, batches)

	t.Run("k matches R", func(t *testing.T) {
		t.Parallel()

		for i := 0; i < tau; i++ {
			for p1 := range identities {
				p1BigR := cipherSuite.Curve.ScalarBaseMult(batches[p1].PreSignatures[i].K)
				for p2 := range identities {
					p2BigR, _ := batches[p2].PreSignatures[i].BigR.Get(identities[p1])
					require.True(t, p1BigR.Equal(p2BigR))
				}
			}
		}
	})

	t.Run("transcripts recorded the same data", func(t *testing.T) {
		t.Parallel()
		label := "gimme"
		ok := integration_test_utils.TranscriptAtSameState(label, transcripts)
		require.True(t, ok)
	})
}
