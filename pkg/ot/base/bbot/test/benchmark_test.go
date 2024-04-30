package bbot_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/testutils/require"
	bbot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot/test/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

func BenchmarkBBOT(b *testing.B) {
	// Create MPC scenario
	scenario, err := ot_testutils.GenerateScenario()
	require.NoError(b, err)

	// Set the parameters to be used in the benchmark
	pp := &ot_testutils.OtParams{
		SessionId: testutils.SampleSessionId(crand.Reader),
		Xi:        128,
		L:         4,
		Curve:     k256.NewCurve(),
	}

	// Run the benchmark
	b.ResetTimer()
	for range b.N {
		sender, receiver, err := bbot_testutils.CreateParticipants(scenario, crand.Reader, pp, pp)
		require.NoError(b, err)

		_, _, err = bbot_testutils.RunROT(sender, receiver, nil)
		require.NoError(b, err)
	}

	// Report the per-party metrics
	b.ReportMetric(float64(b.Elapsed().Milliseconds())/(float64(b.N)*2), "ms/party")
}
