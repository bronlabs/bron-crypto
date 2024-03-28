package sample_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha"
	"github.com/copperexchange/krypton-primitives/pkg/network"
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
	h := sha3.New256
	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	var participants []*setup.Participant
	internal.RunMeasurement(500, "sample_round1", func(i int) {
		allIdentities, err := ttu.MakeTestIdentities(cipherSuite, 3)
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
	h := sha3.New256
	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	var participants []*setup.Participant
	var r2InsU []network.RoundMessages[*setup.Round1P2P]
	internal.RunMeasurement(500, "sample_round2", func(i int) {
		allIdentities, err := ttu.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		participants, err = testutils.MakeSetupParticipants(curve, allIdentities, crand.Reader)
		require.NoError(t, err)
		r1OutsU, err := testutils.DoSetupRound1(participants)
		require.NoError(t, err)
		r2InsU = ttu.MapUnicastO2I(participants, r1OutsU)
	}, func() {
		testutils.DoSetupRound2(participants, r2InsU)
	})
}
func Test_MeasureConstantTime_round3(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	var participants []*setup.Participant
	var r2InsU []network.RoundMessages[*setup.Round1P2P]
	var r3InsU []network.RoundMessages[*setup.Round2P2P]
	internal.RunMeasurement(500, "sample_round3", func(i int) {
		allIdentities, err := ttu.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		participants, err = testutils.MakeSetupParticipants(curve, allIdentities, crand.Reader)
		require.NoError(t, err)
		r1OutsU, err := testutils.DoSetupRound1(participants)
		require.NoError(t, err)
		r2InsU = ttu.MapUnicastO2I(participants, r1OutsU)
		r2OutsU, err := testutils.DoSetupRound2(participants, r2InsU)
		require.NoError(t, err)
		r3InsU = ttu.MapUnicastO2I(participants, r2OutsU)
	}, func() {
		testutils.DoSetupRound3(participants, r3InsU)
	})
}

func Test_MeasureConstantTime_dosample(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	var participants []*sample.Participant

	internal.RunMeasurement(500, "sample_dosample", func(i int) {
		allIdentities, err := ttu.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		protocol, err := ttu.MakeProtocol(curve, allIdentities)
		require.NoError(t, err)
		allPairwiseSeeds, err := doSetup(curve, allIdentities)
		require.NoError(t, err)
		seeds := make([]przs.PairWiseSeeds, 3)
		for j := range allIdentities {
			seeds[j] = allPairwiseSeeds[j]
		}
		seededPrng, err := chacha.NewChachaPRNG(nil, nil)
		require.NoError(t, err)
		participants, err = testutils.MakeSampleParticipants(protocol, allIdentities, seeds, seededPrng, nil)
		require.NoError(t, err)
	}, func() {
		testutils.DoSample(participants)
	})
}
