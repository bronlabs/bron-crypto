package sample_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero/przs"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero/przs/sample"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero/przs/setup"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero/przs/test_utils"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	curve := k256.New()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	var participants []*setup.Participant
	internal.RunMeasurement(500, "sample_round1", func(i int) {
		allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, 3)
		require.NoError(t, err)
		participants, err = test_utils.MakeSetupParticipants(curve, allIdentities, crand.Reader)
		require.NoError(t, err)
	}, func() {
		test_utils.DoSetupRound1(participants)
	})
}
func Test_MeasureConstantTime_round2(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.New()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	var participants []*setup.Participant
	var r2InsU []map[helper_types.IdentityHash]*setup.Round1P2P
	internal.RunMeasurement(500, "sample_round2", func(i int) {
		allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, 3)
		require.NoError(t, err)
		participants, err = test_utils.MakeSetupParticipants(curve, allIdentities, crand.Reader)
		require.NoError(t, err)
		r1OutsU, err := test_utils.DoSetupRound1(participants)
		require.NoError(t, err)
		r2InsU = test_utils.MapSetupRound1OutputsToRound2Inputs(participants, r1OutsU)
	}, func() {
		test_utils.DoSetupRound2(participants, r2InsU)
	})
}
func Test_MeasureConstantTime_round3(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.New()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	var participants []*setup.Participant
	var r2InsU []map[helper_types.IdentityHash]*setup.Round1P2P
	var r3InsU []map[helper_types.IdentityHash]*setup.Round2P2P
	internal.RunMeasurement(500, "sample_round3", func(i int) {
		allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, 3)
		require.NoError(t, err)
		participants, err = test_utils.MakeSetupParticipants(curve, allIdentities, crand.Reader)
		require.NoError(t, err)
		r1OutsU, err := test_utils.DoSetupRound1(participants)
		require.NoError(t, err)
		r2InsU = test_utils.MapSetupRound1OutputsToRound2Inputs(participants, r1OutsU)
		r2OutsU, err := test_utils.DoSetupRound2(participants, r2InsU)
		require.NoError(t, err)
		r3InsU = test_utils.MapSetupRound2OutputsToRound3Inputs(participants, r2OutsU)
	}, func() {
		test_utils.DoSetupRound3(participants, r3InsU)
	})
}

func Test_MeasureConstantTime_dosample(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.New()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	var participants []*sample.Participant

	internal.RunMeasurement(500, "sample_dosample", func(i int) {
		allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, 3)
		require.NoError(t, err)
		cohortConfig := &integration.CohortConfig{
			CipherSuite:  cipherSuite,
			Participants: hashset.NewHashSet(allIdentities),
		}
		require.NoError(t, err)
		allPairwiseSeeds, err := doSetup(curve, allIdentities)
		require.NoError(t, err)
		seeds := make([]przs.PairwiseSeeds, 3)
		for j := range allIdentities {
			seeds[j] = allPairwiseSeeds[j]
		}
		participants, err = test_utils.MakeSampleParticipants(cohortConfig, allIdentities, seeds)
		require.NoError(t, err)
	}, func() {
		test_utils.DoSample(participants)
	})
}
