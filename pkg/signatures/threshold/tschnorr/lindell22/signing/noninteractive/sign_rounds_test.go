package noninteractive_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	integration_test_utils "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing/noninteractive"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing/noninteractive/test_utils"
)

func Test_SignHappyPath(t *testing.T) {
	t.Parallel()

	curve := edwards25519.New()
	hashFunc := sha512.New
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hashFunc,
	}
	prng := crand.Reader
	threshold := 3
	n := 5
	sid := []byte("sessionId")
	tau := 64
	message := []byte("Lorem ipsum")
	transcriptAppLabel := "Lindell2022NonInteractiveSignTest"

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

	shards, err := trusted_dealer.Keygen(cohort, prng)
	require.NoError(t, err)

	for i := 0; i < tau; i++ {
		preSignatureIndex := i
		t.Run(fmt.Sprintf("valid signature %d", preSignatureIndex), func(t *testing.T) {
			t.Parallel()

			partialSignatures := make([]*lindell22.PartialSignature, threshold)
			for i := 0; i < threshold; i++ {
				cosigner, err2 := noninteractive.NewCosigner(identities[i], shards[identities[i].Hash()], cohort, identities[:threshold], 0, batches[i], prng)
				require.NoError(t, err2)
				partialSignatures[i], err = cosigner.ProducePartialSignature(message)
			}

			signature, err := signing.Aggregate(partialSignatures...)
			require.NoError(t, err)

			err = eddsa.Verify(curve, hashFunc, signature, shards[identities[0].Hash()].SigningKeyShare.PublicKey, message)
			require.NoError(t, err)
		})
	}
}
