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
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
	interactive_signing "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/signing/interactive"
)

// testing with too many participants will slow down the fuzzer and it may cause the fuzzer to timeout or memory issue
var (
	maxParticipants = 3
	// maxNumberOfPreSignatures = 10
	cn = randomisedFischlin.Name
)

// we assume that input curves and hash functions are valid
var (
	allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve()}
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

// func FuzzNonInteractiveSigning(f *testing.F) {
// 	f.Fuzz(func(t *testing.T, data []byte) {
// 		fz, n, message, cipherSuite := setup(t, data)
// 		// do DKG
// 		identities, shards := doDkg(t, cipherSuite, n)
// 		// non-interactive signing
// 		doNonInteractiveSigning(t, cipherSuite, n, fz, identities, shards, message)
// 	})
// }

func setup(t *testing.T, data []byte) (*fuzz.Fuzzer, int, []byte, types.SigningSuite) {
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
	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	return fz, n, message, cipherSuite
}

// func doNonInteractiveSigning(t *testing.T, cipherSuite types.SigningSuite, n int, fz *fuzz.Fuzzer, identities []types.IdentityKey, shards ds.HashMap[types.IdentityKey, *lindell17.Shard], message []byte) {
// 	t.Helper()

// 	aliceIdx := 0
// 	bobIdx := 1
// 	tau := maxNumberOfPreSignatures
// 	protocolConfig, err := ttu.MakePreSignedThresholdSignatureProtocol(cipherSuite, identities, lindell17.Threshold, identities, identities[0])
// 	require.NoError(t, err)
// 	var sid []byte
// 	fz.Fuzz(&sid)
// 	preSignatureIndex := 0
// 	fz.Fuzz(&preSignatureIndex)
// 	preSignatureIndex = preSignatureIndex % tau
// 	if preSignatureIndex < 0 {
// 		preSignatureIndex = -preSignatureIndex
// 	}
// 	fmt.Println("sid: ", sid, "preSignatureIndex: ", preSignatureIndex)
// 	transcripts := ttu.MakeTranscripts("TEST", identities)
// 	participants, err := noninteractive_testutils.MakePreGenParticipants(tau, identities, sid, protocolConfig, transcripts)
// 	if len(sid) == 0 {
// 		if errs.IsArgument(err) {
// 			t.Skip()
// 		}
// 	}
// 	require.NoError(t, err)

// 	batches, err := noninteractive_testutils.DoLindell2017PreGen(participants)
// 	require.NoError(t, err)

// 	aliceShard, exists := shards.Get(identities[aliceIdx])
// 	require.True(t, exists)
// 	alice, err := noninteractive_signing.NewCosigner(sid, protocolConfig, identities[aliceIdx].(types.AuthKey), aliceShard, batches[aliceIdx], preSignatureIndex, identities[bobIdx], nil, crand.Reader)
// 	require.NoError(t, err)

// 	bobShard, exists := shards.Get(identities[bobIdx])
// 	require.True(t, exists)
// 	bob, err := noninteractive_signing.NewCosigner(sid, protocolConfig, identities[bobIdx].(types.AuthKey), bobShard, batches[bobIdx], preSignatureIndex, identities[aliceIdx], nil, crand.Reader)
// 	require.NoError(t, err)

// 	partialSignature, err := alice.ProducePartialSignature(message)
// 	require.NoError(t, err)

// 	signature, err := bob.ProduceSignature(partialSignature, message)
// 	require.NoError(t, err)

// 	// signature is valid
// 	for _, identity := range identities {
// 		shard, exists := shards.Get(identity)
// 		require.True(t, exists)
// 		err := ecdsa.Verify(signature, cipherSuite.Hash(), shard.SigningKeyShare.PublicKey, message)
// 		require.NoError(t, err)
// 	}
// }

func doDkg(t *testing.T, cipherSuite types.SigningSuite, n int) ([]types.IdentityKey, ds.Map[types.IdentityKey, *lindell17.Shard]) {
	t.Helper()

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, lindell17.Threshold, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)
	return identities, shards
}

func doInteractiveSigning(t *testing.T, cipherSuite types.SigningSuite, fz *fuzz.Fuzzer, identities []types.IdentityKey, shards ds.Map[types.IdentityKey, *lindell17.Shard], message []byte) {
	t.Helper()

	var sessionId []byte
	fz.Fuzz(&sessionId)
	alice := identities[0]
	bob := identities[1]
	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, lindell17.Threshold, []types.IdentityKey{alice, bob})
	require.NoError(t, err)

	aliceShard, exists := shards.Get(alice)
	require.True(t, exists)
	primary, err := interactive_signing.NewPrimaryCosigner(sessionId, alice.(types.AuthKey), bob, aliceShard, protocol, cn, nil, crand.Reader)
	if err != nil {
		if errs.IsArgument(err) {
			t.Skip()
		}
	}
	require.NotNil(t, primary)
	require.NoError(t, err)

	bobShard, exists := shards.Get(bob)
	require.True(t, exists)
	secondary, err := interactive_signing.NewSecondaryCosigner(sessionId, bob.(types.AuthKey), alice, bobShard, protocol, cn, nil, crand.Reader)
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

	err = ecdsa.Verify(signature, cipherSuite.Hash(), bobShard.SigningKeyShare.PublicKey, message)
	require.NoError(t, err)
}
