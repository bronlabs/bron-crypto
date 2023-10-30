package fuzz

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/rand"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/interactive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/noninteractive_signing"
	noninteractive_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/noninteractive_signing/testutils"
)

// testing with too many participants will slow down the fuzzer and it may cause the fuzzer to timeout or memory issue
var (
	maxParticipants          = 5
	maxNumberOfPreSignatures = 10
)

// we assume that input curves and hash functions are valid
var (
	allCurves = []curves.Curve{k256.New(), p256.New()}
	allHashes = []func() hash.Hash{sha256.New}
)

func FuzzInteractiveSigning(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz, n, message, cipherSuite := setup(t, data)
		// do DKG
		identities, shards := doDkg(t, cipherSuite, n)
		// interactive signing
		doInteractiveSigning(t, cipherSuite, fz, identities, shards, message)
	})
}

func FuzzNonInteractiveSigning(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz, n, message, cipherSuite := setup(t, data)
		// do DKG
		identities, shards := doDkg(t, cipherSuite, n)
		// non-interactive signing
		doNonInteractiveSigning(t, cipherSuite, n, fz, identities, shards, message)
	})
}

func setup(t *testing.T, data []byte) (*fuzz.Fuzzer, int, []byte, *integration.CipherSuite) {
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
	prng := rand.New(rand.NewSource(randomSeed))
	curveIndex = prng.Intn(len(allCurves))
	hashIndex = prng.Intn(len(allHashes))
	n = prng.Intn(maxParticipants-2) + 2 // n is between 2 and 10
	fmt.Println("curveIndex: ", curveIndex, "hashIndex: ", hashIndex, "n: ", n, "randomSeed: ", randomSeed, "message: ", message)
	curve := allCurves[curveIndex%len(allCurves)]
	h := allHashes[hashIndex%len(allHashes)]
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}
	return fz, n, message, cipherSuite
}

func doNonInteractiveSigning(t *testing.T, cipherSuite *integration.CipherSuite, n int, fz *fuzz.Fuzzer, identities []integration.IdentityKey, shards map[types.IdentityHash]*lindell17.Shard, message []byte) {
	t.Helper()

	aliceIdx := 0
	bobIdx := 1
	tau := maxNumberOfPreSignatures
	cohort := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.LINDELL17,
			Threshold:            lindell17.Threshold,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}
	var sid []byte
	fz.Fuzz(&sid)
	preSignatureIndex := 0
	fz.Fuzz(&preSignatureIndex)
	preSignatureIndex = preSignatureIndex % tau
	if preSignatureIndex < 0 {
		preSignatureIndex = -preSignatureIndex
	}
	fmt.Println("sid: ", sid, "preSignatureIndex: ", preSignatureIndex)
	transcripts := integration_testutils.MakeTranscripts("TEST", identities)
	participants, err := noninteractive_testutils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
	if len(sid) == 0 {
		if errs.IsInvalidArgument(err) {
			t.Skip()
		}
	}
	require.NoError(t, err)

	batches, err := noninteractive_testutils.DoLindell2017PreGen(participants)
	require.NoError(t, err)

	aliceShard := shards[identities[aliceIdx].Hash()]
	alice, err := noninteractive_signing.NewCosigner(cohort, identities[aliceIdx], aliceShard, batches[aliceIdx], preSignatureIndex, identities[bobIdx], sid, nil, crand.Reader)
	require.NoError(t, err)

	bobShard := shards[identities[bobIdx].Hash()]
	bob, err := noninteractive_signing.NewCosigner(cohort, identities[bobIdx], bobShard, batches[bobIdx], preSignatureIndex, identities[aliceIdx], sid, nil, crand.Reader)
	require.NoError(t, err)

	partialSignature, err := alice.ProducePartialSignature(message)
	require.NoError(t, err)

	signature, err := bob.ProduceSignature(partialSignature, message)
	require.NoError(t, err)

	// signature is valid
	for _, identity := range identities {
		shard := shards[identity.Hash()]
		err := ecdsa.Verify(signature, cipherSuite.Hash, shard.SigningKeyShare.PublicKey, message)
		require.NoError(t, err)
	}
}

func doDkg(t *testing.T, cipherSuite *integration.CipherSuite, n int) ([]integration.IdentityKey, map[types.IdentityHash]*lindell17.Shard) {
	t.Helper()

	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.LINDELL17,
			Threshold:            lindell17.Threshold,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}

	shards, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(t, err)
	return identities, shards
}

func doInteractiveSigning(t *testing.T, cipherSuite *integration.CipherSuite, fz *fuzz.Fuzzer, identities []integration.IdentityKey, shards map[types.IdentityHash]*lindell17.Shard, message []byte) {
	t.Helper()

	var sessionId []byte
	fz.Fuzz(&sessionId)
	alice := identities[0]
	bob := identities[1]
	cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL17, identities, lindell17.Threshold, []integration.IdentityKey{alice, bob})
	require.NoError(t, err)

	aliceShard := shards[alice.Hash()]
	primary, err := interactive_signing.NewPrimaryCosigner(alice, bob, aliceShard, cohortConfig, sessionId, nil, crand.Reader)
	if err != nil {
		if errs.IsInvalidArgument(err) {
			t.Skip()
		}
	}
	require.NotNil(t, primary)
	require.NoError(t, err)

	bobShard := shards[bob.Hash()]
	secondary, err := interactive_signing.NewSecondaryCosigner(bob, alice, bobShard, cohortConfig, sessionId, nil, crand.Reader)
	require.NotNil(t, secondary)
	require.NoError(t, err)

	r1, err := primary.Round1()
	require.NoError(t, err)

	r2, err := secondary.Round2(r1)
	require.NoError(t, err)

	r3, err := primary.Round3(r2)
	require.NoError(t, err)

	r4, err := secondary.Round4(r3, message)
	require.NoError(t, err)

	signature, err := primary.Round5(r4, message)
	require.NoError(t, err)

	err = ecdsa.Verify(signature, cipherSuite.Hash, bobShard.SigningKeyShare.PublicKey, message)
	require.NoError(t, err)
}
