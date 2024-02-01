package dkg_test

import (
	"crypto/sha256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integrationTestutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/testutils"
	"github.com/stretchr/testify/require"
	"testing"
)

func Benchmark_Dkg(b *testing.B) {
	cipherSuite := &integration.CipherSuite{
		Curve: k256.NewCurve(),
		Hash:  sha256.New,
	}
	uniqueSessionId := []byte("benchmarkSessionId")
	threshold := 2
	n := 3

	identities, err := integrationTestutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(b, err)
	cohortConfig, err := integrationTestutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		participants, err := testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
		require.NoError(b, err)

		r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
		require.NoError(b, err)

		r2InsB, r2InsU := integrationTestutils.MapO2I(participants, r1OutsB, r1OutsU)
		r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
		require.NoError(b, err)

		r3Ins := integrationTestutils.MapBroadcastO2I(participants, r2Outs)
		_, err = testutils.DoDkgRound3(participants, r3Ins)
		require.NoError(b, err)
	}
}
