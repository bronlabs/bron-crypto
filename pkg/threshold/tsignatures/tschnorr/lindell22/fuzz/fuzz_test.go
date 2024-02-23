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
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	interactive_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/interactive/testutils"
)

// testing with too many participants will slow down the fuzzer and it may cause the fuzzer to timeout or memory issue
var (
	maxParticipants = 5
	// maxNumberOfPreSignatures = 10
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

// func FuzzNonInteractiveSigning(f *testing.F) {
// 	f.Fuzz(func(t *testing.T, data []byte) {
// 		fz, n, threshold, message, cipherSuite := setup(t, data)
// 		// do DKG
// 		identities, shards := doDkg(t, cipherSuite, n, threshold)
// 		// do interactive signing
// 		doNonInteractiveSigning(t, fz, threshold, identities, shards, message, cipherSuite)
// 	})
// }

func doInteractiveSigning(t *testing.T, fz *fuzz.Fuzzer, threshold int, identities []types.IdentityKey, shards ds.Map[types.IdentityKey, *lindell22.Shard], message []byte, cipherSuite types.SignatureProtocol) {
	t.Helper()

	flavour := tschnorr.NewEdDsaCompatibleFlavour()
	protocol, _ := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	shard, exists := shards.Get(identities[0])
	require.True(t, exists)
	publicKey := shard.SigningKeyShare.PublicKey

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	var sid []byte
	fz.Fuzz(&sid)
	participants, err := interactive_testutils.MakeParticipants(sid, protocol, identities[:threshold], shards, transcripts, flavour)
	if len(sid) == 0 {
		if errs.IsArgument(err) {
			t.Skip()
		}
	}
	require.NoError(t, err)

	partialSignatures, err := interactive_testutils.RunInteractiveSigning(participants, message)
	require.NoError(t, err)
	require.NotNil(t, partialSignatures)

	signature, err := signing.Aggregate(partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = schnorr.Verify(cipherSuite, &schnorr.PublicKey{A: publicKey}, message, signature)
	require.NoError(t, err)
}

// func doNonInteractiveSigning(t *testing.T, fz *fuzz.Fuzzer, threshold int, identities []types.IdentityKey, shards ds.HashMap[types.IdentityKey, *lindell22.Shard], message []byte, cipherSuite types.SignatureProtocol) {
// 	t.Helper()

// 	var sid []byte
// 	fz.Fuzz(&sid)
// 	tau := maxNumberOfPreSignatures
// 	if len(sid) == 0 {
// 		t.Skip()
// 	}
// 	protocol, _ := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
// 	transcripts := ttu.MakeTranscripts("fuzz-test", identities)
// 	participants, err := noninteractive_testutils.MakePreGenParticipants(tau, identities, sid, protocol, transcripts)
// 	require.NoError(t, err)
// 	batches, err := noninteractive_testutils.DoLindell2022PreGen(participants)
// 	require.NoError(t, err)
// 	partialSignatures := make([]*lindell22.PartialSignature, threshold)
// 	for i := 0; i < threshold; i++ {
// 		shard := shards[identities[i].Hash()]
// 		cosigner, err2 := noninteractive_signing.NewCosigner(identities[i].(types.AuthKey), shard, protocol, hashset.NewHashSet(identities[:threshold]), 0, batches[i], sid, false, nil, crand.Reader)
// 		require.NoError(t, err2)
// 		partialSignatures[i], err = cosigner.ProducePartialSignature(message)
// 		require.NoError(t, err)
// 	}
// 	signature, err := interactive_signing.Aggregate(partialSignatures...)
// 	require.NoError(t, err)
// 	shard := shards[identities[0].Hash()]
// 	err = schnorr.Verify(cipherSuite, &schnorr.PublicKey{A: shard.SigningKeyShare.PublicKey}, message, signature)
// 	require.NoError(t, err)
// }

func doDkg(t *testing.T, cipherSuite types.SignatureProtocol, n, threshold int) ([]types.IdentityKey, ds.Map[types.IdentityKey, *lindell22.Shard]) {
	t.Helper()
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(t, err)
	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)
	return identities, shards
}

func setup(t *testing.T, data []byte) (*fuzz.Fuzzer, int, int, []byte, types.SignatureProtocol) {
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
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)
	return fz, n, threshold, message, cipherSuite
}
