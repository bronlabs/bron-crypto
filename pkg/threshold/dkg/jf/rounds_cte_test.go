package jf_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/test/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	var identities []types.IdentityKey
	var config types.ThresholdProtocol
	var uniqueSessionId []byte
	var participants []*jf.Participant

	internal.RunMeasurement(500, "jf_round1", func(i int) {
		identities, err = ttu.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		config, err = ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, 2)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_testutils.RunAgreeOnRandom(cipherSuite.Curve(), identities, crand.Reader)
		require.NoError(t, err)
		participants, err = testutils.MakeParticipants(uniqueSessionId, config, identities, randomisedFischlin.Name, nil)
		require.NoError(t, err)
	}, func() {
		testutils.DoDkgRound1(participants)
	})
}

func Test_MeasureConstantTime_round2(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	var identities []types.IdentityKey
	var config types.ThresholdProtocol
	var uniqueSessionId []byte
	var participants []*jf.Participant
	var r1OutsB []*jf.Round1Broadcast
	var r1OutsU []network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P]

	internal.RunMeasurement(500, "jf_round2", func(i int) {
		identities, err = ttu.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		config, err = ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, 2)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_testutils.RunAgreeOnRandom(cipherSuite.Curve(), identities, crand.Reader)
		require.NoError(t, err)
		participants, err = testutils.MakeParticipants(uniqueSessionId, config, identities, randomisedFischlin.Name, nil)
		require.NoError(t, err)
		r1OutsB, r1OutsU, err = testutils.DoDkgRound1(participants)
		require.NoError(t, err)
	}, func() {
		ttu.MapO2I(participants, r1OutsB, r1OutsU)
	})
}

func Test_MeasureConstantTime_round3(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	var identities []types.IdentityKey
	var config types.ThresholdProtocol
	var uniqueSessionId []byte
	var participants []*jf.Participant
	var r1OutsB []*jf.Round1Broadcast
	var r1OutsU []network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P]
	var r2InsB []network.RoundMessages[types.ThresholdProtocol, *jf.Round1Broadcast]
	var r2InsU []network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P]
	var r2Outs []*jf.Round2Broadcast
	var r3Ins []network.RoundMessages[types.ThresholdProtocol, *jf.Round2Broadcast]

	internal.RunMeasurement(500, "jf_round3", func(i int) {
		identities, err = ttu.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		config, err = ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, 2)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_testutils.RunAgreeOnRandom(cipherSuite.Curve(), identities, crand.Reader)
		require.NoError(t, err)
		participants, err = testutils.MakeParticipants(uniqueSessionId, config, identities, randomisedFischlin.Name, nil)
		require.NoError(t, err)
		r1OutsB, r1OutsU, err = testutils.DoDkgRound1(participants)
		require.NoError(t, err)
		r2InsB, r2InsU = ttu.MapO2I(participants, r1OutsB, r1OutsU)
		r2Outs, err = testutils.DoDkgRound2(participants, r2InsB, r2InsU)
		require.NoError(t, err)
		r3Ins = ttu.MapBroadcastO2I(participants, r2Outs)
	}, func() {
		testutils.DoDkgRound3(participants, r3Ins)
	})
}
