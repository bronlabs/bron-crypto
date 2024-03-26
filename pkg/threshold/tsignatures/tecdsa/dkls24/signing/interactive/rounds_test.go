package interactive_test

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/fkechacha20"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/testutils"
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

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	_, shards, err := testutils.RunDKG(curve, protocol, allIdentities)
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
		identities := make([]types.IdentityKey, threshold)
		selectedShards := make([]*dkls24.Shard, threshold)
		for i, index := range combinationIndices {
			identities[i] = allIdentities[index]
			selectedShards[i] = shards[index]
		}
		t.Run(fmt.Sprintf("running the happy path with identities %v", identities), func(t *testing.T) {
			t.Parallel()
			err := testutils.RunInteractiveSign(protocol, identities, selectedShards, message, seededPrng, nil)
			require.NoError(t, err)
		})
	}
}

// This test runs the protocol correctly once, and then runs it again with one party
// replaying messages from the previous run. The test checks that the signing fails.
func testFailForReplayedMessages(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int, message []byte) {
	t.Helper()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)
	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	_, shards, err := testutils.RunDKG(curve, protocol, allIdentities)
	require.NoError(t, err)

	seededPrng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)

	identities := make([]types.IdentityKey, threshold)
	selectedShards := make([]*dkls24.Shard, threshold)
	for i := 0; i < threshold; i++ {
		identities[i] = allIdentities[i]
		selectedShards[i] = shards[i]
	}
	t.Run(fmt.Sprintf("running the replayed messages unhappy path with identities %v", identities), func(t *testing.T) {
		t.Helper()

		// Run the protocol once.
		participants, err := testutils.MakeInteractiveCosigners(protocol, identities, shards, nil, seededPrng, nil)
		require.NoError(t, err)
		r1OutB, r1OutU, err := testutils.DoInteractiveSignRound1(participants)
		require.NoError(t, err)
		r2InB, r2InU := ttu.MapO2I(participants, r1OutB, r1OutU)
		r2OutB, r2OutU, err := testutils.DoInteractiveSignRound2(participants, r2InB, r2InU)
		require.NoError(t, err)
		r3InB, r3InU := ttu.MapO2I(participants, r2OutB, r2OutU)
		partialSignatures, err := testutils.DoInteractiveSignRound3(participants, r3InB, r3InU, message)
		require.NoError(t, err)
		producedSignatures, err := testutils.RunSignatureAggregation(protocol, identities, participants, partialSignatures, message)
		require.NoError(t, err)
		err = testutils.CheckInteractiveSignResults(producedSignatures)
		require.NoError(t, err)

		// Run the protocol again (with a fresh sid), with the first participant replaying messages from the previous run.
		participants2, err := testutils.MakeInteractiveCosigners(protocol, identities, shards, nil, seededPrng, nil)
		require.NoError(t, err)
		r1OutB2, r1OutU2, err := testutils.DoInteractiveSignRound1(participants2)
		require.NoError(t, err)

		// Party 1 switches his P2P messages to the ones from the previous run.
		r1OutU2[0] = r1OutU[0]
		r2InB2, r2InU2 := ttu.MapO2I(participants2, r1OutB2, r1OutU2)
		_, _, err = testutils.DoInteractiveSignRound2(participants2, r2InB2, r2InU2)
		require.Error(t, err)

		// Run the protocol again with a fresh sid.
		participants3, err := testutils.MakeInteractiveCosigners(protocol, identities, shards, nil, seededPrng, nil)
		require.NoError(t, err)
		r1OutB3, r1OutU3, err := testutils.DoInteractiveSignRound1(participants3)
		require.NoError(t, err)
		r2InB3, r2InU3 := ttu.MapO2I(participants3, r1OutB3, r1OutU3)
		r2OutB3, r2OutU3, err := testutils.DoInteractiveSignRound2(participants3, r2InB3, r2InU3)
		require.NoError(t, err)
		// Party 1 switches his broadcast messages to the ones from the previous run.
		r2OutB3[0] = r2OutB[0]
		r3InB3, r3InU3 := ttu.MapO2I(participants3, r2OutB3, r2OutU3)
		_, err = testutils.DoInteractiveSignRound3(participants3, r3InB3, r3InU3, message)
		require.Error(t, err)
	})
}

// This test sets the SID for the participants to be different before running the
// protocol and checks that the signing fails.
func testFailForDifferentSID(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int, message []byte) {
	t.Helper()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	_, shards, err := testutils.RunDKG(curve, protocol, allIdentities)
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
	selectedShards := make([]*dkls24.Shard, threshold)
	for i := 0; i < threshold; i++ {
		identities[i] = allIdentities[i]
		selectedShards[i] = shards[i]
	}
	t.Run(fmt.Sprintf("running the diverging SID unhappy path with identities %v", identities), func(t *testing.T) {
		t.Parallel()
		err := testutils.RunInteractiveSign(protocol, identities, selectedShards, message, seededPrng, sids)
		require.Error(t, err)
	})

}
