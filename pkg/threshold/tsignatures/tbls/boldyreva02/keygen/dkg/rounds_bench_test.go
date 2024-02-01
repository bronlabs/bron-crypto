package dkg_test

import (
	"crypto/sha256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integrationTestutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/testutils"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func Benchmark_Dkg(b *testing.B) {
	h := sha256.New
	uniqueSessionId := []byte("benchmarkSessionId")
	threshold := 2
	n := 3

	b.Run("G1", func(b *testing.B) {
		curve := bls12381.NewG1()
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}

		identities, err := integrationTestutils.MakeTestIdentities(cipherSuite, n)
		require.NoError(b, err)
		cohortConfig, err := integrationTestutils.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
		require.NoError(b, err)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchmarkDkg[bls12381.G1](b, uniqueSessionId, cohortConfig, identities, nil)
		}
	})

	b.Run("G2", func(b *testing.B) {
		curve := bls12381.NewG2()
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}

		identities, err := integrationTestutils.MakeTestIdentities(cipherSuite, n)
		require.NoError(b, err)
		cohortConfig, err := integrationTestutils.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
		require.NoError(b, err)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchmarkDkg[bls12381.G2](b, uniqueSessionId, cohortConfig, identities, nil)
		}
	})
}

func benchmarkDkg[K bls.KeySubGroup](t require.TestingT, uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) {
	participants, err := testutils.MakeDkgParticipants[K](uniqueSessionId, cohortConfig, identities, prngs)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)

	r2InsB, r2InsU := integrationTestutils.MapO2I(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)

	r3Ins := integrationTestutils.MapBroadcastO2I(participants, r2Outs)
	_, err = testutils.DoDkgRound3(participants, r3Ins)
	require.NoError(t, err)
}
