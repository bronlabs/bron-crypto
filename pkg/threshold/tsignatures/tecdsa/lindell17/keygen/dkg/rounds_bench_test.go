package dkg_test

import (
	"crypto/sha256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	testutils2 "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	gennaroDkgTestutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/dkg/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"testing"
)

func Benchmark_Dkg(b *testing.B) {
	cipherSuite, err := testutils2.MakeSignatureProtocol(k256.NewCurve(), sha256.New)
	require.NoError(b, err)

	uniqueSessionId := []byte("benchmarkSessionId")

	identities, err := testutils2.MakeTestIdentities(cipherSuite, 3)
	require.NoError(b, err)
	cohortConfig, err := testutils2.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(b, err)

	xscripts := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		xscripts[i] = hagrid.NewTranscript("Lindell 2017 DKG", nil)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gennaroParticipants, err := gennaroDkgTestutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, randomisedFischlin.Name, nil)
		require.NoError(b, err)

		r1OutsB, r1OutsU, err := gennaroDkgTestutils.DoDkgRound1(gennaroParticipants)
		require.NoError(b, err)

		r2InsB, r2InsU := testutils2.MapO2I(gennaroParticipants, r1OutsB, r1OutsU)
		r2Outs, err := gennaroDkgTestutils.DoDkgRound2(gennaroParticipants, r2InsB, r2InsU)
		require.NoError(b, err)

		r3Ins := testutils2.MapBroadcastO2I(gennaroParticipants, r2Outs)
		signingKeyShares, publicKeyShares, err := gennaroDkgTestutils.DoDkgRound3(gennaroParticipants, r3Ins)
		require.NoError(b, err)

		lindellParticipants, err := testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, signingKeyShares, publicKeyShares, xscripts, nil)
		require.NoError(b, err)

		r1o, err := testutils.DoDkgRound1(lindellParticipants)
		require.NoError(b, err)

		r2i := testutils2.MapBroadcastO2I(lindellParticipants, r1o)
		r2o, err := testutils.DoDkgRound2(lindellParticipants, r2i)
		require.NoError(b, err)

		r3i := testutils2.MapBroadcastO2I(lindellParticipants, r2o)
		r3o, err := testutils.DoDkgRound3(lindellParticipants, r3i)
		require.NoError(b, err)

		r4i := testutils2.MapBroadcastO2I(lindellParticipants, r3o)
		r4o, err := testutils.DoDkgRound4(lindellParticipants, r4i)
		require.NoError(b, err)

		r5i := testutils2.MapUnicastO2I(lindellParticipants, r4o)
		r5o, err := testutils.DoDkgRound5(lindellParticipants, r5i)
		require.NoError(b, err)

		r6i := testutils2.MapUnicastO2I(lindellParticipants, r5o)
		r6o, err := testutils.DoDkgRound6(lindellParticipants, r6i)
		require.NoError(b, err)

		r7i := testutils2.MapUnicastO2I(lindellParticipants, r6o)
		r7o, err := testutils.DoDkgRound7(lindellParticipants, r7i)
		require.NoError(b, err)

		r8i := testutils2.MapUnicastO2I(lindellParticipants, r7o)
		_, err = testutils.DoDkgRound8(lindellParticipants, r8i)
		require.NoError(b, err)
	}
}
