package lindell22_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	hashing_bip340 "github.com/copperexchange/krypton-primitives/pkg/hashing/bip340"
	lindell22_noninteractive_signing "github.com/copperexchange/krypton-primitives/pkg/krypton/noninteractive_signing/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/krypton/noninteractive_signing/tschnorr/lindell22/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/bip340"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
)

func Test_SignNonInteractiveThresholdEdDSA(t *testing.T) {
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

	shards, err := trusted_dealer.Keygen(cohort, prng)
	require.NoError(t, err)

	for i := 0; i < tau; i++ {
		preSignatureIndex := i
		t.Run(fmt.Sprintf("valid signature %d", preSignatureIndex), func(t *testing.T) {
			t.Parallel()

			partialSignatures := make([]*lindell22.PartialSignature, threshold)
			for i := 0; i < threshold; i++ {
				cosigner, err2 := lindell22_noninteractive_signing.NewCosigner(identities[i], shards[identities[i].Hash()], cohort, hashset.NewHashSet(identities[:threshold]), 0, batches[i], sid, false, nil, prng)
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

func Test_SignNonInteractiveThresholdBIP340(t *testing.T) {
	t.Parallel()

	curve := k256.New()
	hashFunc := hashing_bip340.NewBip340HashChallenge
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

	shards, err := trusted_dealer.Keygen(cohort, prng)
	require.NoError(t, err)

	for i := 0; i < tau; i++ {
		preSignatureIndex := i
		t.Run(fmt.Sprintf("valid signature %d", preSignatureIndex), func(t *testing.T) {
			t.Parallel()

			partialSignatures := make([]*lindell22.PartialSignature, threshold)
			for i := 0; i < threshold; i++ {
				cosigner, err2 := lindell22_noninteractive_signing.NewCosigner(identities[i], shards[identities[i].Hash()], cohort, hashset.NewHashSet(identities[:threshold]), 0, batches[i], sid, true, nil, prng)
				require.NoError(t, err2)
				partialSignatures[i], err = cosigner.ProducePartialSignature(message)
			}

			signature, err := signing.Aggregate(partialSignatures...)
			require.NoError(t, err)

			bipSignature := &bip340.Signature{
				R: signature.R,
				S: signature.Z,
			}

			err = bip340.Verify(&bip340.PublicKey{P: shards[identities[0].Hash()].SigningKeyShare.PublicKey}, bipSignature, message)
			require.NoError(t, err)
		})
	}
}
