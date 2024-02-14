package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/testutils"
)

func TestRunProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiling test in short mode")
	}
	if os.Getenv("PROFILE_T") == "" || os.Getenv("PROFILE_N") == "" {
		t.Skip("skipping profiling test missing parameter")
	}
	th, _ := strconv.Atoi(os.Getenv("PROFILE_T"))
	n, _ := strconv.Atoi(os.Getenv("PROFILE_N"))
	for i := 0; i < 1000; i++ {
		testHappyPath(t, th, n)
	}
}

func testHappyPath(t *testing.T, threshold, n int) {
	t.Helper()

	curve := bls12381.NewG1()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, sha256.New)
	require.NoError(t, err)

	inG1 := curve.Name() == bls12381.NameG1
	inG1s := make([]bool, n)
	for i := 0; i < n; i++ {
		inG1s[i] = inG1
	}

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, threshold)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeDkgParticipants(uniqueSessionId, protocol, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Equal(t, out.Size(), protocol.Participants().Size()-1)
	}

	r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)

	r3Ins := ttu.MapBroadcastO2I(participants, r2Outs)
	shards, err := testutils.DoDkgRound3(participants, r3Ins)
	require.NoError(t, err)
	for _, shard := range shards {
		err = shard.Validate(protocol)
		require.NoError(t, err)
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, thresholdConfig := range []struct {
		t int
		n int
	}{
		{t: 2, n: 2},
		{t: 2, n: 3},
		{t: 3, n: 3},
	} {
		boundedThresholdConfig := thresholdConfig
		t.Run(fmt.Sprintf("Happy path with inG1=%t and t=%d and n=%d", true, boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
			t.Parallel()
			testHappyPath(t, boundedThresholdConfig.t, boundedThresholdConfig.n)
		})
	}
}
