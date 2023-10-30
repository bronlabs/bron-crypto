package noninteractive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/noninteractive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/noninteractive_signing/testutils"
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

			identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
			require.NoError(t, err)

			cohort, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL17, identities, lindell17.Threshold, identities)
			require.NoError(t, err)

			message := []byte("Hello World!")
			require.NoError(t, err)

			shards, err := trusted_dealer.Keygen(cohort, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, shards)
			require.Len(t, shards, cohort.Protocol.TotalParties)

			transcripts := testutils.MakeTranscripts(transcriptAppLabel, identities)
			participants, err := testutils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
			require.NoError(t, err)

			batches, err := testutils.DoLindell2017PreGen(participants)
			require.NoError(t, err)
			require.NotNil(t, batches)

			aliceIdx := 0
			bobIdx := 1

			for i := 0; i < tau; i++ {
				preSignatureIndex := i
				t.Run(fmt.Sprintf("presignature index: %d", preSignatureIndex), func(t *testing.T) {
					t.Parallel()

					alice, err := noninteractive_signing.NewCosigner(cohort, identities[aliceIdx], shards[identities[aliceIdx].Hash()], batches[aliceIdx], preSignatureIndex, identities[bobIdx], sid, nil, prng)
					require.NoError(t, err)

					bob, err := noninteractive_signing.NewCosigner(cohort, identities[bobIdx], shards[identities[bobIdx].Hash()], batches[bobIdx], preSignatureIndex, identities[aliceIdx], sid, nil, prng)
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
