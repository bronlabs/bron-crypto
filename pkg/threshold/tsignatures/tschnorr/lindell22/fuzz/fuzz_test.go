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

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/interactive_signing"
	interactive_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/interactive_signing/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/noninteractive_signing"
	noninteractive_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/noninteractive_signing/testutils"
)

// testing with too many participants will slow down the fuzzer and it may cause the fuzzer to timeout or memory issue
var (
	maxParticipants          = 5
	maxNumberOfPreSignatures = 10
)

// we assume that input curves and hash functions are valid
var (
	allCurves = []curves.Curve{edwards25519.NewCurve()}
	allHashes = []func() hash.Hash{sha512.New}
)

func FuzzInteractiveSigning(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz, n, threshold, message, cipherSuite := setup(t, data)
		// do DKG
		identities, shards := doDkg(t, cipherSuite, n, threshold)
		// do interactive signing
		doInteractiveSigning(t, fz, threshold, identities, shards, message, cipherSuite)
	})
}

func FuzzNonInteractiveSigning(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz, n, threshold, message, cipherSuite := setup(t, data)
		// do DKG
		identities, shards := doDkg(t, cipherSuite, n, threshold)
		// do interactive signing
		doNonInteractiveSigning(t, fz, threshold, identities, shards, message, cipherSuite)
	})
}

func doInteractiveSigning(t *testing.T, fz *fuzz.Fuzzer, threshold int, identities []integration.IdentityKey, shards map[types.IdentityHash]*lindell22.Shard, message []byte, cipherSuite *integration.CipherSuite) {
	t.Helper()

	cohort, _ := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
	shard := shards[identities[0].Hash()]
	publicKey := shard.SigningKeyShare.PublicKey

	transcripts := integration_testutils.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	var sid []byte
	fz.Fuzz(&sid)
	participants, err := interactive_testutils.MakeParticipants(sid, cohort, identities[:threshold], shards, transcripts, false)
	if len(sid) == 0 {
		if errs.IsInvalidArgument(err) {
			t.Skip()
		}
	}
	require.NoError(t, err)

	partialSignatures, err := interactive_testutils.RunInteractiveSigning(participants, message)
	require.NoError(t, err)
	require.NotNil(t, partialSignatures)

	signature, err := interactive_signing.Aggregate(partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = schnorr.Verify(cipherSuite, &schnorr.PublicKey{A: publicKey}, message, signature)
	require.NoError(t, err)
}

func doNonInteractiveSigning(t *testing.T, fz *fuzz.Fuzzer, threshold int, identities []integration.IdentityKey, shards map[types.IdentityHash]*lindell22.Shard, message []byte, cipherSuite *integration.CipherSuite) {
	t.Helper()

	var sid []byte
	fz.Fuzz(&sid)
	tau := maxNumberOfPreSignatures
	if len(sid) == 0 {
		t.Skip()
	}
	cohort, _ := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
	transcripts := integration_testutils.MakeTranscripts("fuzz-test", identities)
	participants, err := noninteractive_testutils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
	require.NoError(t, err)
	batches, err := noninteractive_testutils.DoLindell2022PreGen(participants)
	require.NoError(t, err)
	partialSignatures := make([]*lindell22.PartialSignature, threshold)
	for i := 0; i < threshold; i++ {
		shard := shards[identities[i].Hash()]
		cosigner, err2 := noninteractive_signing.NewCosigner(identities[i].(integration.AuthKey), shard, cohort, hashset.NewHashSet(identities[:threshold]), 0, batches[i], sid, false, nil, crand.Reader)
		require.NoError(t, err2)
		partialSignatures[i], err = cosigner.ProducePartialSignature(message)
		require.NoError(t, err)
	}
	signature, err := interactive_signing.Aggregate(partialSignatures...)
	require.NoError(t, err)
	shard := shards[identities[0].Hash()]
	err = schnorr.Verify(cipherSuite, &schnorr.PublicKey{A: shard.SigningKeyShare.PublicKey}, message, signature)
	require.NoError(t, err)
}

func doDkg(t *testing.T, cipherSuite *integration.CipherSuite, n, threshold int) ([]integration.IdentityKey, map[types.IdentityHash]*lindell22.Shard) {
	t.Helper()
	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohort, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
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
	prng := rand.New(rand.NewSource(randomSeed))
	curveIndex = prng.Intn(len(allCurves))
	hashIndex = prng.Intn(len(allHashes))
	n = prng.Intn(maxParticipants-2) + 2                       // n is between 2 and 10
	threshold := prng.Intn(int(math.Max(float64(n-2), 1))) + 2 // threshold is between 2 and n
	fmt.Println("curveIndex: ", curveIndex, "hashIndex: ", hashIndex, "n: ", n, "randomSeed: ", randomSeed, "message: ", message)
	curve := allCurves[curveIndex%len(allCurves)]
	h := allHashes[hashIndex%len(allHashes)]
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}
	return fz, n, threshold, message, cipherSuite
}
