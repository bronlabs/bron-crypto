package noninteractive_signing_test

// import (
// 	"crypto/sha256"
// 	"testing"

// 	"github.com/stretchr/testify/require"

// 	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
// 	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/noninteractive_signing/testutils"
// )

// func Test_PreGenHappyPath(t *testing.T) {
// 	t.Parallel()

// 	curve := k256.NewCurve()
// 	hash := sha256.New
// 	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hash)
// 	require.NoError(t, err)
// 	threshold := 2
// 	n := 3
// 	sid := []byte("sessionId")
// 	tau := 64
// 	transcriptAppLabel := "Lindell2017PreGenTest"

// 	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
// 	require.NoError(t, err)

// 	protocol, err := ttu.MakePreSignedThresholdSignatureProtocol(curve, identities, threshold, hash, identities, identities[0])
// 	require.NoError(t, err)

// 	transcripts := ttu.MakeTranscripts(transcriptAppLabel, identities)
// 	participants, err := testutils.MakePreGenParticipants(tau, identities, sid, protocol, transcripts)
// 	require.NoError(t, err)

// 	batches, err := testutils.DoLindell2017PreGen(participants)
// 	require.NoError(t, err)
// 	require.NotNil(t, batches)

// 	t.Run("R is the same in each batch", func(t *testing.T) {
// 		t.Parallel()

// 		for i := 0; i < tau; i++ {
// 			for p1 := 0; p1 < len(participants); p1++ {
// 				for p2 := p1 + 1; p2 < len(participants); p2++ {
// 					l, exists := batches[p1].PreSignatures[i].BigR.Get(participants[p2].IdentityKey())
// 					require.True(t, exists)
// 					r, exists := batches[p2].PreSignatures[i].BigR.Get(participants[p1].IdentityKey())
// 					require.True(t, exists)
// 					require.True(t, l.Equal(r))
// 				}
// 			}
// 		}
// 	})

// 	t.Run("transcripts recoded the same data", func(t *testing.T) {
// 		t.Parallel()
// 		ok, err := ttu.TranscriptAtSameState("gimme", transcripts)
// 		require.NoError(t, err)
// 		require.True(t, ok)
// 	})
// }
