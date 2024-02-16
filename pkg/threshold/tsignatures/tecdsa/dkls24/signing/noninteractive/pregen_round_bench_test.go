package noninteractiveSigning_test

import (
	"crypto/sha256"
	testutils2 "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/testutils"
)

func Benchmark_PreGenTau100(b *testing.B) {
	sessionId := []byte("benchmarkSessionId")
	hashFunc := sha256.New
	curve := k256.NewCurve()
	signatureProtocol, err := testutils2.MakeSignatureProtocol(curve, hashFunc)
	require.NoError(b, err)
	threshold := 2
	n := 3

	allIdentities, err := testutils2.MakeTestIdentities(signatureProtocol, n)
	require.NoError(b, err)

	cohortConfig, err := testutils2.MakeThresholdSignatureProtocol(signatureProtocol, allIdentities, threshold, allIdentities)
	require.NoError(b, err)

	_, shards, err := testutils.RunDKG(curve, cohortConfig, allIdentities)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preGenParties := testutils.MakePreGenParticipants(b, sessionId, cohortConfig, allIdentities, shards, nil, nil)
		_ = testutils.RunPreGen(b, preGenParties)
	}
}
