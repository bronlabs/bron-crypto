package noninteractive_signing_test

// import (
// 	crand "crypto/rand"
// 	"crypto/sha512"
// 	"fmt"
// 	"testing"

// 	"github.com/stretchr/testify/require"

// 	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/types"
// 	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
// 	hashing_bip340 "github.com/copperexchange/krypton-primitives/pkg/hashing/bip340"
// 	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/bip340"
// 	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/interactive_signing"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/noninteractive_signing"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/noninteractive_signing/testutils"
// )

// func Test_SignNonInteractiveThresholdEdDSA(t *testing.T) {
// 	t.Parallel()

// 	curve := edwards25519.NewCurve()
// 	hashFunc := sha512.New
// 	cipherSuite := &types.SignatureProtocol{
// 		Curve: curve,
// 		Hash:  hashFunc,
// 	}
// 	prng := crand.Reader
// 	threshold := 3
// 	n := 5
// 	sid := []byte("sessionId")
// 	tau := 64
// 	message := []byte("Lorem ipsum")
// 	transcriptAppLabel := "Lindell2022NonInteractiveSignTest"

// 	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
// 	require.NoError(t, err)

// 	cohort, err := ttu.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
// 	require.NoError(t, err)

// 	transcripts := ttu.MakeTranscripts(transcriptAppLabel, identities)
// 	participants, err := testutils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
// 	require.NoError(t, err)

// 	batches, err := testutils.DoLindell2022PreGen(participants)
// 	require.NoError(t, err)
// 	require.NotNil(t, batches)

// 	shards, err := trusted_dealer.Keygen(cohort, prng)
// 	require.NoError(t, err)

// 	for i := 0; i < tau; i++ {
// 		preSignatureIndex := i
// 		t.Run(fmt.Sprintf("valid signature %d", preSignatureIndex), func(t *testing.T) {
// 			t.Parallel()

// 			partialSignatures := make([]*lindell22.PartialSignature, threshold)
// 			for i := 0; i < threshold; i++ {
// 				cosigner, err2 := noninteractive_signing.NewCosigner(identities[i].(types.AuthKey), shards[identities[i].Hash()], cohort, hashset.NewHashSet(identities[:threshold]), 0, batches[i], sid, false, nil, prng)
// 				require.NoError(t, err2)
// 				partialSignatures[i], err = cosigner.ProducePartialSignature(message)
// 			}

// 			signature, err := interactive_signing.Aggregate(partialSignatures...)
// 			require.NoError(t, err)

// 			err = schnorr.Verify(cipherSuite, &schnorr.PublicKey{A: shards[identities[0].Hash()].SigningKeyShare.PublicKey}, message, signature)
// 			require.NoError(t, err)
// 		})
// 	}
// }

// func Test_SignNonInteractiveThresholdBIP340(t *testing.T) {
// 	t.Parallel()

// 	curve := k256.NewCurve()
// 	hashFunc := hashing_bip340.NewBip340HashChallenge
// 	cipherSuite := &types.SignatureProtocol{
// 		Curve: curve,
// 		Hash:  hashFunc,
// 	}
// 	prng := crand.Reader
// 	threshold := 3
// 	n := 5
// 	sid := []byte("sessionId")
// 	tau := 64
// 	message := []byte("Lorem ipsum")
// 	transcriptAppLabel := "Lindell2022NonInteractiveSignTest"

// 	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
// 	require.NoError(t, err)

// 	cohort, err := ttu.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
// 	require.NoError(t, err)

// 	transcripts := ttu.MakeTranscripts(transcriptAppLabel, identities)
// 	participants, err := testutils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
// 	require.NoError(t, err)

// 	batches, err := testutils.DoLindell2022PreGen(participants)
// 	require.NoError(t, err)
// 	require.NotNil(t, batches)

// 	shards, err := trusted_dealer.Keygen(cohort, prng)
// 	require.NoError(t, err)

// 	for i := 0; i < tau; i++ {
// 		preSignatureIndex := i
// 		t.Run(fmt.Sprintf("valid signature %d", preSignatureIndex), func(t *testing.T) {
// 			t.Parallel()

// 			partialSignatures := make([]*lindell22.PartialSignature, threshold)
// 			for i := 0; i < threshold; i++ {
// 				cosigner, err2 := noninteractive_signing.NewCosigner(identities[i].(types.AuthKey), shards[identities[i].Hash()], cohort, hashset.NewHashSet(identities[:threshold]), 0, batches[i], sid, true, nil, prng)
// 				require.NoError(t, err2)
// 				partialSignatures[i], err = cosigner.ProducePartialSignature(message)
// 			}

// 			signature, err := interactive_signing.Aggregate(partialSignatures...)
// 			require.NoError(t, err)

// 			bipSignature := &bip340.Signature{
// 				R: signature.R,
// 				S: signature.S,
// 			}

// 			err = bip340.Verify(&bip340.PublicKey{A: shards[identities[0].Hash()].SigningKeyShare.PublicKey}, bipSignature, message)
// 			require.NoError(t, err)
// 		})
// 	}
// }
