package noninteractive_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	integration_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/ecdsa"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/keygen/trusted_dealer"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/signing/noninteractive"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/signing/noninteractive/test_utils"
	"github.com/stretchr/testify/require"
)

func Test_NonInteractiveSignHappyPath(t *testing.T) {
	t.Parallel()

	sid := []byte("sessionId")
	n := 3
	tau := 16
	prng := crand.Reader
	transcriptAppLabel := "Lindell2017NonInteractiveSignTest"

	supportedCurves := []*curves.Curve{
		curves.P256(),
		curves.K256(),
	}

	for _, c := range supportedCurves {
		curve := c
		t.Run(fmt.Sprintf("Lindell 2017 for %s", curve.Name), func(t *testing.T) {
			t.Parallel()

			cipherSuite := &integration.CipherSuite{
				Curve: curve,
				Hash:  sha256.New,
			}

			identities, err := integration_test_utils.MakeIdentities(cipherSuite, n)
			require.NoError(t, err)

			cohort, err := integration_test_utils.MakeCohort(cipherSuite, protocol.LINDELL17, identities, lindell17.Threshold, identities)
			require.NoError(t, err)

			message := []byte("Hello World!")
			require.NoError(t, err)

			shards, err := trusted_dealer.Keygen(cohort, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, shards)
			require.Len(t, shards, cohort.TotalParties)

			transcripts := test_utils.MakeTranscripts(transcriptAppLabel, identities)
			participants, err := test_utils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
			require.NoError(t, err)

			batches, err := test_utils.DoLindell2017PreGen(participants)
			require.NoError(t, err)
			require.NotNil(t, batches)

			aliceIdx := 0
			bobIdx := 1

			for i := 0; i < tau; i++ {
				preSignatureIndex := i
				t.Run(fmt.Sprintf("presignature index: %d", preSignatureIndex), func(t *testing.T) {
					t.Parallel()

					alice, err := noninteractive.NewCosigner(cohort, identities[aliceIdx], shards[identities[aliceIdx]], batches[aliceIdx], preSignatureIndex, identities[bobIdx], prng)
					require.NoError(t, err)

					bob, err := noninteractive.NewCosigner(cohort, identities[bobIdx], shards[identities[bobIdx]], batches[bobIdx], preSignatureIndex, identities[aliceIdx], prng)
					require.NoError(t, err)

					partialSignature, err := alice.ProducePartialSignature(message)
					require.NoError(t, err)

					signature, err := bob.ProduceSignature(partialSignature, message)
					require.NoError(t, err)

					// signature is valid
					for _, identity := range identities {
						err := ecdsa.Verify(signature, cipherSuite.Hash, shards[identity].SigningKeyShare.PublicKey, message)
						require.NoError(t, err)
					}
				})
			}
		})
	}
}
