package noninteractive_signing_test

import (
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integrationTestutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	nonInteractiveSigningTestutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/noninteractive_signing/testutils"
)

const transcriptAppLabel = "benchmarkLindell2022PreGen"

func Benchmark_PreGen_Tau100(b *testing.B) {
	curve := edwards25519.NewCurve()
	hashFunc := sha512.New
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hashFunc,
	}
	threshold := 2
	n := 3
	sid := []byte("benchmarkSessionId")
	tau := 100

	identities, err := integrationTestutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(b, err)

	cohort, err := integrationTestutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, threshold, identities)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		transcripts := integrationTestutils.MakeTranscripts(transcriptAppLabel, identities)

		b.StartTimer()
		participants, err := nonInteractiveSigningTestutils.MakePreGenParticipants(tau, identities, sid, cohort, transcripts)
		require.NoError(b, err)
		_, err = nonInteractiveSigningTestutils.DoLindell2022PreGen(participants)
		require.NoError(b, err)
	}
}
