package lindell17_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/krypton/noninteractive_signing/tecdsa/lindell17/testutils"
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

	identities, err := integration_testutils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohort, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL17, identities, threshold, identities)
	require.NoError(t, err)

	transcripts := integration_testutils.MakeTranscripts(transcriptAppLabel, identities)
	participants, err := testutils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
	require.NoError(t, err)

	batches, err := testutils.DoLindell2017PreGen(participants)
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
		ok, err := integration_testutils.TranscriptAtSameState("gimme", transcripts)
		require.NoError(t, err)
		require.True(t, ok)
	})
}
