package lindell17_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	integration_test_utils "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	lindell17_noninteractive_signing "github.com/copperexchange/knox-primitives/pkg/knox/noninteractive_signing/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/knox/noninteractive_signing/tecdsa/lindell17/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/keygen/trusted_dealer"
)

func Test_NonInteractiveSignHappyPath(t *testing.T) {
	t.Parallel()

	sid := []byte("sessionId")
	n := 3
	tau := 16
	prng := crand.Reader
	transcriptAppLabel := "Lindell2017NonInteractiveSignTest"

	supportedCurves := []curves.Curve{
		p256.New(),
		k256.New(),
	}

	for _, c := range supportedCurves {
		curve := c
		t.Run(fmt.Sprintf("Lindell 2017 for %s", curve.Name()), func(t *testing.T) {
			t.Parallel()

			cipherSuite := &integration.CipherSuite{
				Curve: p256.New(),
				Hash:  sha256.New,
			}

			identities, err := integration_test_utils.MakeIdentities(cipherSuite, n)
			require.NoError(t, err)

			cohort, err := integration_test_utils.MakeCohortProtocol(cipherSuite, protocols.LINDELL17, identities, lindell17.Threshold, identities)
			require.NoError(t, err)

			message := []byte("Hello World!")
			require.NoError(t, err)

			shards, err := trusted_dealer.Keygen(cohort, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, shards)
			require.Len(t, shards, cohort.Protocol.TotalParties)

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

					alice, err := lindell17_noninteractive_signing.NewCosigner(cohort, identities[aliceIdx], shards[identities[aliceIdx].Hash()], batches[aliceIdx], preSignatureIndex, identities[bobIdx], sid, nil, prng)
					require.NoError(t, err)

					bob, err := lindell17_noninteractive_signing.NewCosigner(cohort, identities[bobIdx], shards[identities[bobIdx].Hash()], batches[bobIdx], preSignatureIndex, identities[aliceIdx], sid, nil, prng)
					require.NoError(t, err)

					partialSignature, err := alice.ProducePartialSignature(message)
					require.NoError(t, err)

					signature, err := bob.ProduceSignature(partialSignature, message)
					require.NoError(t, err)

					// signature is valid
					for _, identity := range identities {
						err := ecdsa.Verify(signature, cipherSuite.Hash, shards[identity.Hash()].SigningKeyShare.PublicKey, message)
						require.NoError(t, err)
					}
				})
			}
		})
	}
}
