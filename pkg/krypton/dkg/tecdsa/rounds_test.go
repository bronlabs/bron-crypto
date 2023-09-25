package tecdsa_test

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	testutils_integration "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/krypton/dkg/tecdsa/testutils"
)

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) {
	t.Helper()
	if testing.Short() {
		t.Skip()
	}

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := testutils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := testutils_integration.MakeCohortProtocol(cipherSuite, protocols.DKLS23, identities, threshold, identities)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)

	r2InsB := testutils.MapDkgRoundArray(participants, r1OutsB)
	r2OutsB, err := testutils.DoDkgRound2(participants, r2InsB)
	require.NoError(t, err)

	r3InsB := testutils.MapDkgRoundArray(participants, r2OutsB)
	r3OutsB, r3OutsU, err := testutils.DoDkgRound3(participants, r3InsB)
	require.NoError(t, err)

	r4InsB, r4InsU := testutils.MapDkgRoundP2P(participants, r3OutsB, r3OutsU)
	r4OutsB, r4OutsU, err := testutils.DoDkgRound4(participants, r4InsB, r4InsU)
	require.NoError(t, err)

	r5InsB, r5InsU := testutils.MapDkgRoundP2P(participants, r4OutsB, r4OutsU)
	r5OutsB, r5OutsU, err := testutils.DoDkgRound5(participants, r5InsB, r5InsU)
	require.NoError(t, err)

	r6InsB, r6InsU := testutils.MapDkgRoundP2P(participants, r5OutsB, r5OutsU)
	r6OutsB, r6OutsU, err := testutils.DoDkgRound6(participants, r6InsB, r6InsU)
	require.NoError(t, err)

	r7InsB, r7InsU := testutils.MapDkgRoundP2P(participants, r6OutsB, r6OutsU)
	r7OutsB, r7OutsU, err := testutils.DoDkgRound7(participants, r7InsB, r7InsU)
	require.NoError(t, err)

	r8InsB, r8InsU := testutils.MapDkgRoundP2P(participants, r7OutsB, r7OutsU)
	r8OutsU, err := testutils.DoDkgRound8(participants, r8InsB, r8InsU)
	require.NoError(t, err)

	r9InsU := testutils.MapDkgRound(participants, r8OutsU)
	r9OutsU, err := testutils.DoDkgRound9(participants, r9InsU)
	require.NoError(t, err)

	r10InsU := testutils.MapDkgRound(participants, r9OutsU)
	r10OutsU, err := testutils.DoDkgRound10(participants, r10InsU)
	require.NoError(t, err)

	r11InsU := testutils.MapDkgRound(participants, r10OutsU)
	r11OutsU, err := testutils.DoDkgRound11(participants, r11InsU)
	require.NoError(t, err)

	r12InsU := testutils.MapDkgRound(participants, r11OutsU)
	shards, err := testutils.DoDkgRound12(participants, r12InsU)
	require.NoError(t, err)
	require.Len(t, shards, n)

	// we are combining different protocols and we have tests in their respective packages.
	for _, shard := range shards {
		require.NotNil(t, shard.SigningKeyShare())
		require.NoError(t, shard.SigningKeyShare().Validate())
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{k256.New(), p256.New()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha256.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
