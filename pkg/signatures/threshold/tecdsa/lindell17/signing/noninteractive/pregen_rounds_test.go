package noninteractive_test

import (
	"bytes"
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	lin17_noninteractive_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/signing/noninteractive/test_utils"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_PreGenHappyPath(t *testing.T) {
	t.Parallel()

	curve := curves.K256()
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

	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohort, err := test_utils.MakeCohort(cipherSuite, protocol.LINDELL17, identities, threshold, identities)
	require.NoError(t, err)

	transcripts := lin17_noninteractive_test_utils.MakeTranscripts(transcriptAppLabel, identities)
	participants, err := lin17_noninteractive_test_utils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
	require.NoError(t, err)

	batches, err := lin17_noninteractive_test_utils.DoLindell2017PreGen(participants)
	require.NoError(t, err)
	require.NotNil(t, batches)

	t.Run("R is the same in each batch", func(t *testing.T) {
		t.Parallel()

		for i := 0; i < tau; i++ {
			for p1 := 0; p1 < len(participants); p1++ {
				for p2 := p1 + 1; p2 < len(participants); p2++ {
					l := batches[p1].PreSignatures[i].BigR[participants[p2].GetIdentityKey()]
					r := batches[p2].PreSignatures[i].BigR[participants[p1].GetIdentityKey()]
					require.True(t, l.Equal(r))
				}
			}
		}
	})

	t.Run("transcripts recoded the same data", func(t *testing.T) {
		label := []byte("gimme")
		for i := 0; i < len(transcripts); i++ {
			l := transcripts[i].ExtractBytes(label, 128)
			for j := i + 1; j < len(transcripts); j++ {
				r := transcripts[j].ExtractBytes(label, 128)
				require.True(t, bytes.Equal(l, r))
			}
		}
	})
}
