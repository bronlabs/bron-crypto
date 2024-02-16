package noninteractive_signing_test

//
//import (
//	"crypto/sha256"
//	testutils2 "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
//	"testing"
//
//	"github.com/stretchr/testify/require"
//
//	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
//	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
//	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/noninteractive_signing/testutils"
//)
//
//func Benchmark_PreGenTau100(b *testing.B) {
//	sid := []byte("benchmarkSessionId")
//	n := 3
//	tau := 100
//	transcriptAppLabel := "Lindell2017NonInteractiveSignTest"
//	curve := k256.NewCurve()
//	hashFunc := sha256.New
//	cipherSuite, err := testutils2.MakeSignatureProtocol(curve, hashFunc)
//	require.NoError(b, err)
//
//	identities, err := testutils2.MakeTestIdentities(cipherSuite, n)
//	require.NoError(b, err)
//
//	cohort, err := testutils2.MakeThresholdSignatureProtocol(cipherSuite, identities, lindell17.Threshold, identities)
//	require.NoError(b, err)
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		b.StopTimer()
//		transcripts := testutils2.MakeTranscripts(transcriptAppLabel, identities)
//
//		b.StartTimer()
//		participants, err := testutils.(tau, identities, sid, cohort, transcripts)
//		require.NoError(b, err)
//		_, err = testutils.DoLindell2017PreGen(participants)
//		require.NoError(b, err)
//	}
//}
