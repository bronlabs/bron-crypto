package fuzz

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"math"
	"math/rand"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	integration_test_utils "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing"
	interactive_test_utils "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing/interactive/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing/noninteractive"
	noninteractive_test_utils "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing/noninteractive/test_utils"
)

// testing with too many participants will slow down the fuzzer and it may cause the fuzzer to timeout or memory issue
var (
	maxParticipants          = 5
	maxNumberOfPreSignatures = 10
)

// we assume that input curves and hash functions are valid
var (
	allCurves = []curves.Curve{edwards25519.New()}
	allHashes = []func() hash.Hash{sha512.New}
)

func FuzzInteractiveSigning(f *testing.F) {
	safePrimeMocker := test_utils.NewSafePrimeMocker()
	safePrimeMocker.Mock()
	f.Fuzz(func(t *testing.T, data []byte) {
		fz, n, threshold, message, cipherSuite := setup(t, data)
		// do DKG
		identities, shards := doDkg(t, cipherSuite, n, threshold)
		// do interactive signing
		doInteractiveSigning(t, fz, threshold, identities, shards, message, cipherSuite)
	})
}

func FuzzNonInteractiveSigning(f *testing.F) {
	safePrimeMocker := test_utils.NewSafePrimeMocker()
	safePrimeMocker.Mock()
	f.Fuzz(func(t *testing.T, data []byte) {
		fz, n, threshold, message, cipherSuite := setup(t, data)
		// do DKG
		identities, shards := doDkg(t, cipherSuite, n, threshold)
		// do interactive signing
		doNonInteractiveSigning(t, fz, threshold, identities, shards, message, cipherSuite)
	})
}

func doInteractiveSigning(t *testing.T, fz *fuzz.Fuzzer, threshold int, identities []integration.IdentityKey, shards map[integration.IdentityHash]*lindell22.Shard, message []byte, cipherSuite *integration.CipherSuite) {
	t.Helper()

	cohort, _ := integration_test_utils.MakeCohort(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
	shard := shards[identities[0].Hash()]
	publicKey := shard.SigningKeyShare.PublicKey

	transcripts := integration_test_utils.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	var sid []byte
	fz.Fuzz(&sid)
	participants, err := interactive_test_utils.MakeParticipants(sid, cohort, identities[:threshold], shards, transcripts)
	if len(sid) == 0 {
		if errs.IsInvalidArgument(err) {
			t.Skip()
		}
	}
	require.NoError(t, err)

	partialSignatures, err := interactive_test_utils.DoInteractiveSigning(participants, message)
	require.NoError(t, err)
	require.NotNil(t, partialSignatures)

	signature, err := signing.Aggregate(partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = eddsa.Verify(cipherSuite.Curve, cipherSuite.Hash, signature, publicKey, message)
	require.NoError(t, err)
}

func doNonInteractiveSigning(t *testing.T, fz *fuzz.Fuzzer, threshold int, identities []integration.IdentityKey, shards map[integration.IdentityHash]*lindell22.Shard, message []byte, cipherSuite *integration.CipherSuite) {
	t.Helper()

	var sid []byte
	fz.Fuzz(&sid)
	tau := maxNumberOfPreSignatures
	if len(sid) == 0 {
		t.Skip()
	}
	cohort, _ := integration_test_utils.MakeCohort(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
	transcripts := integration_test_utils.MakeTranscripts("fuzz-test", identities)
	participants, err := noninteractive_test_utils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
	require.NoError(t, err)
	batches, err := noninteractive_test_utils.DoLindell2022PreGen(participants)
	require.NoError(t, err)
	partialSignatures := make([]*lindell22.PartialSignature, threshold)
	for i := 0; i < threshold; i++ {
		shard := shards[identities[i].Hash()]
		cosigner, err2 := noninteractive.NewCosigner(identities[i], shard, cohort, identities[:threshold], 0, batches[i], sid, nil, crand.Reader)
		require.NoError(t, err2)
		partialSignatures[i], err = cosigner.ProducePartialSignature(message)
		require.NoError(t, err)
	}
	signature, err := signing.Aggregate(partialSignatures...)
	require.NoError(t, err)
	shard := shards[identities[0].Hash()]
	err = eddsa.Verify(cipherSuite.Curve, cipherSuite.Hash, signature, shard.SigningKeyShare.PublicKey, message)
	require.NoError(t, err)
}

func doDkg(t *testing.T, cipherSuite *integration.CipherSuite, n, threshold int) ([]integration.IdentityKey, map[integration.IdentityHash]*lindell22.Shard) {
	t.Helper()
	identities, err := integration_test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohort, err := integration_test_utils.MakeCohort(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
	require.NoError(t, err)
	shards, err := trusted_dealer.Keygen(cohort, crand.Reader)
	require.NoError(t, err)
	return identities, shards
}

func setup(t *testing.T, data []byte) (*fuzz.Fuzzer, int, int, []byte, *integration.CipherSuite) {
	t.Helper()

	// setup random variables according to the data seed
	fz := fuzz.NewFromGoFuzz(data).NilChance(0.05)
	var curveIndex int
	var hashIndex int
	var n int
	var randomSeed int64
	fz.Fuzz(&curveIndex)
	fz.Fuzz(&hashIndex)
	fz.Fuzz(&randomSeed)
	var message []byte
	fz.Fuzz(&message)
	if len(message) == 0 {
		message = []byte{1}
	}
	random := rand.New(rand.NewSource(randomSeed))
	curveIndex = random.Intn(len(allCurves))
	hashIndex = random.Intn(len(allHashes))
	n = random.Intn(maxParticipants-2) + 2                       // n is between 2 and 10
	threshold := random.Intn(int(math.Max(float64(n-2), 1))) + 2 // threshold is between 2 and n
	fmt.Println("curveIndex: ", curveIndex, "hashIndex: ", hashIndex, "n: ", n, "randomSeed: ", randomSeed, "message: ", message)
	curve := allCurves[curveIndex%len(allCurves)]
	h := allHashes[hashIndex%len(allHashes)]
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}
	return fz, n, threshold, message, cipherSuite
}
