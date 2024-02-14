package fuzz

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"math"
	"math/rand"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	dklstu "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/keygen/dkg/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/testutils"
)

// testing with too many participants will slow down the fuzzer and it may cause the fuzzer to timeout or memory issue
var (
	maxParticipants = 5
)

// we assume that input curves and hash functions are valid
var (
	allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve()}
	allHashes = []func() hash.Hash{sha256.New, sha3.New256}
)

func FuzzInteractiveSigning(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz, n, threshold, message, cipherSuite := setup(t, data)
		// fuzz identities
		identities := fuzzIdentityKeys(t, fz, cipherSuite, n)
		// do DKG
		shards := doDkg(t, fz, cipherSuite, threshold, identities)
		// do interactive signing
		doInteractiveSigning(t, threshold, identities, shards, message, cipherSuite)
	})
}

func fuzzIdentityKeys(t *testing.T, fz *fuzz.Fuzzer, cipherSuite types.SignatureProtocol, n int) []types.IdentityKey {
	t.Helper()
	var secretValue []byte
	fz.Fuzz(&secretValue)
	identities := make([]types.IdentityKey, n)
	for i := 0; i < len(identities); i++ {
		commitedScalar, err := cipherSuite.Curve().ScalarField().Hash(secretValue)
		require.NoError(t, err)
		identity, err := ttu.MakeTestIdentity(cipherSuite, commitedScalar)
		identities[i] = identity
		require.NoError(t, err)
	}
	return identities
}

func doInteractiveSigning(t *testing.T, threshold int, identities []types.IdentityKey, shards []*dkls24.Shard, message []byte, cipherSuite types.SignatureProtocol) {
	t.Helper()
	cohortConfig, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(t, err)
	signerIdentities := identities[:threshold]
	seededPrng, err := chacha.NewChachaPRNG(nil, nil)
	require.NoError(t, err)
	err = testutils.RunInteractiveSign(cohortConfig, signerIdentities, shards, message, seededPrng, nil)
	require.NoError(t, err)
}

func doDkg(t *testing.T, fz *fuzz.Fuzzer, cipherSuite types.SignatureProtocol, threshold int, identities []types.IdentityKey) []*dkls24.Shard {
	t.Helper()
	var sid []byte
	fz.Fuzz(&sid)
	_, _, _, shards, err := dklstu.KeyGen(cipherSuite.Curve(), cipherSuite.Hash(), threshold, len(identities), identities, sid)
	if err != nil {
		if errs.IsDuplicate(err) || errs.IsCount(err) {
			t.Skip("too many participants")
		}
	}
	require.NoError(t, err)
	return shards
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
