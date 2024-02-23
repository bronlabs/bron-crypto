package noninteractive_signing_test

import (
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/noninteractive/testutils"
)

func Test_PreGenHappyPath(t *testing.T) {
	t.Parallel()

	curve := edwards25519.NewCurve()
	hashFunc := sha512.New
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hashFunc)
	require.NoError(t, err)
	threshold := 3
	n := 5
	sid := []byte("sessionId")
	transcriptAppLabel := "Lindell2022PreGenTest"

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, threshold)
	require.NoError(t, err)

	transcripts := ttu.MakeTranscripts(transcriptAppLabel, identities)
	participants, err := testutils.MakePreGenParticipants(identities, sid, protocol, transcripts)
	require.NoError(t, err)

	ppm, err := testutils.DoLindell2022PreGen(participants)
	require.NoError(t, err)
	require.NotNil(t, ppm)

	t.Run("k matches R", func(t *testing.T) {
		t.Parallel()

		for p1 := range identities {
			p1BigR := cipherSuite.Curve().ScalarBaseMult(ppm[p1].PrivateMaterial.K1)
			p1BigR2 := cipherSuite.Curve().ScalarBaseMult(ppm[p1].PrivateMaterial.K2)
			for p2 := range identities {
				if identities[p1].Equal(identities[p2]) {
					continue
				}

				p2BigR, exists := ppm[p2].PreSignature.BigR1.Get(identities[p1])
				require.True(t, exists)
				p2BigR2, exists := ppm[p2].PreSignature.BigR2.Get(identities[p1])
				require.True(t, exists)
				require.True(t, p1BigR.Equal(p2BigR))
				require.True(t, p1BigR2.Equal(p2BigR2))
			}
		}
	})

	t.Run("transcripts recorded the same data", func(t *testing.T) {
		t.Parallel()
		label := "gimme"
		ok, err := ttu.TranscriptAtSameState(label, transcripts)
		require.NoError(t, err)
		require.True(t, ok)
	})
}
