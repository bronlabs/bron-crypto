package noninteractive_signing_test

import (
	"crypto/sha512"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	nonInteractiveSigningTestutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/noninteractive_signing/testutils"
)

const transcriptAppLabel = "benchmarkLindell2022PreGen"

func Benchmark_PreGen_Tau100(b *testing.B) {
	curve := edwards25519.NewCurve()
	hashFunc := sha512.New
	cipherSuite, err := testutils.MakeSignatureProtocol(curve, hashFunc)
	require.NoError(b, err)

	threshold := 2
	n := 3
	sid := []byte("benchmarkSessionId")

	identities, err := testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(b, err)

	cohort, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transcripts := testutils.MakeTranscripts(transcriptAppLabel, identities)
		participants, err := nonInteractiveSigningTestutils.MakePreGenParticipants(identities, sid, cohort, transcripts, hashset.NewHashableHashSet(identities...))
		require.NoError(b, err)
		_, err = nonInteractiveSigningTestutils.DoLindell2022PreGen(participants)
		require.NoError(b, err)
	}
}
