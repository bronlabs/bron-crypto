package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	testutils_integration "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"

	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/testutils"
	"github.com/stretchr/testify/require"
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

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha256.New,
	}

	inG1 := curve.Name() == bls12381.G1Name
	inG1s := make([]bool, n)
	for i := 0; i < n; i++ {
		inG1s[i] = inG1
	}

	identities, err := testutils_integration.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := testutils_integration.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.ProduceSharedRandomValue(curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeDkgParticipants(uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.Participants.Len()-1)
	}

	r2InsB, r2InsU := testutils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)

	r3Ins := testutils.MapDkgRound2OutputsToRound3Inputs(participants, r2Outs)
	shards, err := testutils.DoDkgRound3(participants, r3Ins)
	require.NoError(t, err)
	for _, shard := range shards {
		err = shard.Validate(cohortConfig)
		require.NoError(t, err)
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, inG1 := range []bool{true, false} {
		for _, thresholdConfig := range []struct {
			t int
			n int
		}{
			{t: 2, n: 2},
			{t: 2, n: 3},
			{t: 3, n: 3},
		} {
			boundedInG1 := inG1
			boundedThresholdConfig := thresholdConfig
			t.Run(fmt.Sprintf("Happy path with inG1=%t and t=%d and n=%d", boundedInG1, boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
				t.Parallel()
				if boundedInG1 {
					testHappyPath(t, boundedThresholdConfig.t, boundedThresholdConfig.n)
				} else {
					testHappyPath(t, boundedThresholdConfig.t, boundedThresholdConfig.n)
				}
			})
		}
	}
}
