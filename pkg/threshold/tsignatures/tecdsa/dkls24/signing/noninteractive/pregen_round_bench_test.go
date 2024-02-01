package noninteractiveSigning_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integrationTestutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/testutils"
)

func Benchmark_PreGenTau100(b *testing.B) {
	sessionId := []byte("benchmarkSessionId")
	hashFunc := sha256.New
	curve := k256.NewCurve()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hashFunc,
	}
	threshold := 2
	n := 3
	tau := 100

	allIdentities, err := integrationTestutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(b, err)

	cohortConfig, err := integrationTestutils.MakeCohortProtocol(cipherSuite, protocols.DKLS24, allIdentities, threshold, allIdentities)
	require.NoError(b, err)

	shards, err := testutils.RunDKG(cipherSuite.Curve, cohortConfig, allIdentities)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preGenParties := testutils.MakePreGenParticipants(b, tau, sessionId, cohortConfig, allIdentities, shards, nil, nil)
		_ = testutils.RunPreGen(b, preGenParties)
	}
}
