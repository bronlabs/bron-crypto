package interactiveSigning_test

import (
	"crypto/sha256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/testutils"
	"github.com/stretchr/testify/require"
	"testing"
)

func Benchmark_InteractiveSigning(b *testing.B) {
	curve := k256.NewCurve()
	h := sha256.New
	signatureProtocol, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(b, err)

	threshold := 2
	n := 3
	sessionIds := [][]byte{[]byte("benchmarkSessionId"), []byte("benchmarkSessionId"), []byte("benchmarkSessionId")}
	message := []byte("Hello World!")

	allIdentities, err := ttu.MakeTestIdentities(signatureProtocol, n)
	require.NoError(b, err)

	cohortConfig, err := ttu.MakeThresholdSignatureProtocol(signatureProtocol, allIdentities, threshold, allIdentities)
	require.NoError(b, err)

	_, shards, err := testutils.RunDKG(curve, cohortConfig, allIdentities)
	require.NoError(b, err)

	seededPrngFactory, err := chacha.NewChachaPRNG(nil, nil)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		participants, err := testutils.MakeInteractiveCosigners(cohortConfig, allIdentities[:threshold], shards[:threshold], nil, seededPrngFactory, sessionIds[:threshold])
		require.NoError(b, err)

		r1OutB, r1OutU, err := testutils.DoInteractiveSignRound1(participants)
		require.NoError(b, err)

		r2InB, r2InU := ttu.MapO2I(participants, r1OutB, r1OutU)
		r2OutB, r2OutU, err := testutils.DoInteractiveSignRound2(participants, r2InB, r2InU)
		require.NoError(b, err)

		r3InB, r3InU := ttu.MapO2I(participants, r2OutB, r2OutU)
		_, err = testutils.DoInteractiveSignRound3(participants, r3InB, r3InU, message)
		require.NoError(b, err)
	}

}
