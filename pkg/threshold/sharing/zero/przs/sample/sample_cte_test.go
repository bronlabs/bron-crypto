package sample_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/testutils"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	curve := k256.NewCurve()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	var participants []*setup.Participant
	internal.RunMeasurement(500, "sample_round1", func(i int) {
		allIdentities, err := integration_testutils.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		participants, err = testutils.MakeSetupParticipants(curve, allIdentities, crand.Reader)
		require.NoError(t, err)
	}, func() {
		testutils.DoSetupRound1(participants)
	})
}
func Test_MeasureConstantTime_round2(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	var participants []*setup.Participant
	var r2InsU []map[types.IdentityHash]*setup.Round1P2P
	internal.RunMeasurement(500, "sample_round2", func(i int) {
		allIdentities, err := integration_testutils.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		participants, err = testutils.MakeSetupParticipants(curve, allIdentities, crand.Reader)
		require.NoError(t, err)
		r1OutsU, err := testutils.DoSetupRound1(participants)
		require.NoError(t, err)
		r2InsU = integration_testutils.MapUnicastO2I(participants, r1OutsU)
	}, func() {
		testutils.DoSetupRound2(participants, r2InsU)
	})
}
func Test_MeasureConstantTime_round3(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	var participants []*setup.Participant
	var r2InsU []map[types.IdentityHash]*setup.Round1P2P
	var r3InsU []map[types.IdentityHash]*setup.Round2P2P
	internal.RunMeasurement(500, "sample_round3", func(i int) {
		allIdentities, err := integration_testutils.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		participants, err = testutils.MakeSetupParticipants(curve, allIdentities, crand.Reader)
		require.NoError(t, err)
		r1OutsU, err := testutils.DoSetupRound1(participants)
		require.NoError(t, err)
		r2InsU = integration_testutils.MapUnicastO2I(participants, r1OutsU)
		r2OutsU, err := testutils.DoSetupRound2(participants, r2InsU)
		require.NoError(t, err)
		r3InsU = integration_testutils.MapUnicastO2I(participants, r2OutsU)
	}, func() {
		testutils.DoSetupRound3(participants, r3InsU)
	})
}

func Test_MeasureConstantTime_dosample(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	var participants []*sample.Participant

	internal.RunMeasurement(500, "sample_dosample", func(i int) {
		allIdentities, err := integration_testutils.MakeTestIdentities(cipherSuite, 3)
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
		seededPrng, err := chacha20.NewChachaPRNG(nil, nil)
		require.NoError(t, err)
		participants, err = testutils.MakeSampleParticipants(cohortConfig, allIdentities, seeds, seededPrng, nil)
		require.NoError(t, err)
	}, func() {
		testutils.DoSample(participants)
	})
}
