package interactive_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/combinatorics"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23/testutils"
)

var testCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve()}
var testHashFunctions = []func() hash.Hash{sha256.New, sha3.New256}
var testThresholdConfigs = []struct{ t, n int }{
	{t: 2, n: 3},
	{t: 2, n: 2},
	{t: 3, n: 3},
	{t: 3, n: 5},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range testCurves {
		for _, h := range testHashFunctions {
			for _, thresholdConfig := range testThresholdConfigs {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				boundedMessage := []byte("Hello World!")
				t.Run(fmt.Sprintf("Interactive sign happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n, boundedMessage)
				})
			}
		}
	}
}

func Test_UnHappyPath(t *testing.T) {
	t.Parallel()
	if os.Getenv("DEFLAKE_TIME_TEST") == "1" {
		t.Skip("Skipping this test in deflake mode.")
	}
	if testing.Short() {
		t.Skip("Skipping this test in short mode.")
	}
	for _, curve := range testCurves {
		for _, h := range testHashFunctions {
			for _, thresholdConfig := range testThresholdConfigs {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				boundedMessage := []byte("Hello World!")
				t.Run(fmt.Sprintf("Interactive sign unhappy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testFailForDifferentSID(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n, boundedMessage)
					testFailForReplayedMessages(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n, boundedMessage)
				})
			}
		}
	}
}

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int, message []byte) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)

	seededPrng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)

	N := make([]int, n)
	for i := range n {
		N[i] = i
	}

	combinations, err := combinatorics.Combinations(N, uint(threshold))
	require.NoError(t, err)
	if testing.Short() {
		combinations = combinations[:1]
	}
	for _, combinationIndices := range combinations {
		identities := []types.IdentityKey{}
		selectedShards := []*dkls23.Shard{}
		i := 0
		for identity, shard := range shards.Iter() {
			if len(identities) == threshold {
				break
			}
			if slices.Index(combinationIndices, i) == -1 {
				i++
				continue
			}
			identities = append(identities, identity)
			selectedShards = append(selectedShards, shard)
			i++
		}
		t.Run(fmt.Sprintf("running the happy path with identities %v", identities), func(t *testing.T) {
			t.Parallel()
			testutils.RunInteractiveSignHappyPath(t, protocol, identities, selectedShards, message, seededPrng, nil)
		})
	}
}

func splitShards(t *testing.T, shards ds.Map[types.IdentityKey, *dkls23.Shard]) (identities []types.IdentityKey, theirShards []*dkls23.Shard) {
	t.Helper()
	for identity, shard := range shards.Iter() {
		identities = append(identities, identity)
		theirShards = append(theirShards, shard)
	}
	return
}

// This test runs the protocol correctly once, and then runs it again with one party
// replaying messages from the previous run. The test checks that the signing fails.
func testFailForReplayedMessages(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int, message []byte) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)

	var theirShards []*dkls23.Shard
	allIdentities, theirShards = splitShards(t, shards)

	seededPrng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)

	identities := make([]types.IdentityKey, threshold)
	selectedShards := make([]*dkls23.Shard, threshold)
	for i := 0; i < threshold; i++ {
		identities[i] = allIdentities[i]
		selectedShards[i] = theirShards[i]
	}
	t.Run(fmt.Sprintf("running the replayed messages unhappy path with identities %v", identities), func(t *testing.T) {
		t.Helper()

		// Run the protocol once.
		participants, err := testutils.MakeInteractiveCosigners(t, protocol, identities, theirShards, nil, seededPrng, nil)
		require.NoError(t, err)

		r1OutU, err := testutils.DoInteractiveSignRound1(participants)
		require.NoError(t, err)
		r2InU := ttu.MapUnicastO2I(t, participants, r1OutU)
		r2OutU, err := testutils.DoInteractiveSignRound2(participants, r2InU)
		require.NoError(t, err)
		r3InU := ttu.MapUnicastO2I(t, participants, r2OutU)
		r3OutB, r3OutU, err := testutils.DoInteractiveSignRound3(participants, r3InU)
		require.NoError(t, err)
		r4InB, r4InU := ttu.MapO2I(t, participants, r3OutB, r3OutU)
		r4OutB, r4OutU, err := testutils.DoInteractiveSignRound4(participants, r4InB, r4InU)
		require.NoError(t, err)
		r5InB, r5InU := ttu.MapO2I(t, participants, r4OutB, r4OutU)
		partialSignatures, err := testutils.DoInteractiveSignRound5(participants, r5InB, r5InU, message)
		require.NoError(t, err)
		producedSignatures, err := testutils.RunSignatureAggregation(protocol, identities, participants, partialSignatures, message)
		require.NoError(t, err)
		err = testutils.CheckInteractiveSignResults(producedSignatures)
		require.NoError(t, err)

		// Run the protocol again (with a fresh sid), with the first participant replaying messages from the previous run.
		participants2, err := testutils.MakeInteractiveCosigners(t, protocol, identities, theirShards, nil, seededPrng, nil)
		require.NoError(t, err)
		r1OutU2, err := testutils.DoInteractiveSignRound1(participants2)
		require.NoError(t, err)

		// Party 1 switches his P2P messages to the ones from the previous run.
		r2InU2 := ttu.MapUnicastO2I(t, participants2, r1OutU2)
		r2OutU2, err := testutils.DoInteractiveSignRound2(participants2, r2InU2)
		require.NoError(t, err)
		r3InU2 := ttu.MapUnicastO2I(t, participants, r2OutU2)

		r3InU2[0] = r3InU[0]
		_, _, err = testutils.DoInteractiveSignRound3(participants, r3InU2)
		require.Error(t, err)
	})
}

// This test sets the SID for the participants to be different before running the
// protocol and checks that the signing fails.
func testFailForDifferentSID(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int, message []byte) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)

	seededPrng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)

	// Set a divergent SID for the first participant. Since we run it for all
	// possible combinations of shards-identities, this is equivalent to testing
	// with a divergent SID on a different participant each time.
	commonSid := []byte("Our chosen shared 32B session ID")
	divergingSidP1 := []byte("My 32B session ID is different!!")
	sids := make([][]byte, threshold)
	sids[0] = divergingSidP1
	for i := 1; i < threshold; i++ {
		sids[i] = commonSid
	}

	identities := make([]types.IdentityKey, threshold)
	selectedShards := make([]*dkls23.Shard, threshold)
	i := 0
	for identity, shard := range shards.Iter() {
		if i >= threshold {
			break
		}
		identities[i] = identity
		selectedShards[i] = shard
		i++
	}
	t.Run(fmt.Sprintf("running the diverging SID unhappy path with identities %v", identities), func(t *testing.T) {
		t.Parallel()
		err := testutils.RunInteractiveSign(t, protocol, identities, selectedShards, message, seededPrng, sids)
		require.Error(t, err)
	})

}
