package noninteractive_signing_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/signing/noninteractive/testutils"
)

func Test_PreGenHappyPath(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	hash := sha256.New
	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	threshold := 2
	n := 3
	sid := []byte("sessionId")
	transcriptAppLabel := "Lindell2017PreGenTest"

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(t, err)

	transcripts := ttu.MakeTranscripts(transcriptAppLabel, identities)
	participants, err := testutils.MakePreGenParticipants(identities, sid, protocol, transcripts)
	require.NoError(t, err)

	ppms, err := testutils.DoLindell2017PreGen(participants)
	require.NoError(t, err)
	require.NotNil(t, ppms)

	t.Run("all ppms are valid", func(t *testing.T) {
		t.Parallel()
		for i, ppm := range ppms {
			err = ppm.Validate(identities[i], protocol)
			require.NoError(t, err)
		}
	})

	t.Run("R is the same for everyone", func(t *testing.T) {
		t.Parallel()
		for p1 := 0; p1 < len(participants); p1++ {
			for p2 := p1 + 1; p2 < len(participants); p2++ {
				l, exists := ppms[p1].PreSignature.BigR.Get(participants[p2].IdentityKey())
				require.True(t, exists)
				r, exists := ppms[p2].PreSignature.BigR.Get(participants[p1].IdentityKey())
				require.True(t, exists)
				require.True(t, l.Equal(r))
			}
		}
	})

	t.Run("transcripts recoded the same data", func(t *testing.T) {
		t.Parallel()
		ok, err := ttu.TranscriptAtSameState("gimme", transcripts)
		require.NoError(t, err)
		require.True(t, ok)
	})
}
