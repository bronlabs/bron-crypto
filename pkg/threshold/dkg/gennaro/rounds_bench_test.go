package gennaro_test

import (
	"crypto/sha256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	testutils2 "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro/testutils"
	"github.com/stretchr/testify/require"
	"testing"
)

func Benchmark_Dkg(b *testing.B) {
	sessionId := []byte("benchmarkSessionId")
	curve := k256.NewCurve()
	hashFunc := sha256.New
	cipherSuite, err := testutils2.MakeSignatureProtocol(curve, hashFunc)
	require.NoError(b, err)

	identities, err := testutils2.MakeTestIdentities(cipherSuite, 3)
	require.NoError(b, err)

	cohortConfig, err := testutils2.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := testutils.RunDKG(sessionId, cohortConfig, identities)
		require.NoError(b, err)
	}
}
