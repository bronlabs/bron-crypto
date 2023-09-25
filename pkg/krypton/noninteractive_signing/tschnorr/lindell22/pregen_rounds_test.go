package lindell22_test

import (
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/krypton/noninteractive_signing/tschnorr/lindell22/testutils"
)

func Test_PreGenHappyPath(t *testing.T) {
	t.Parallel()

	curve := edwards25519.New()
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

	identities, err := integration_testutils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohort, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
	require.NoError(t, err)

	transcripts := integration_testutils.MakeTranscripts(transcriptAppLabel, identities)
	participants, err := testutils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
	require.NoError(t, err)

	batches, err := testutils.DoLindell2022PreGen(participants)
	require.NoError(t, err)
	require.NotNil(t, batches)

	t.Run("k matches R", func(t *testing.T) {
		t.Parallel()

		for i := 0; i < tau; i++ {
			for p1 := range identities {
				p1BigR := cipherSuite.Curve.ScalarBaseMult(batches[p1].PreSignatures[i].K)
				for p2 := range identities {
					p2BigR := batches[p2].PreSignatures[i].BigR[identities[p1].Hash()]
					require.True(t, p1BigR.Equal(p2BigR))
				}
			}
		}
	})

	t.Run("transcripts recorded the same data", func(t *testing.T) {
		t.Parallel()
		label := "gimme"
		ok, err := integration_testutils.TranscriptAtSameState(label, transcripts)
		require.NoError(t, err)
		require.True(t, ok)
	})
}
