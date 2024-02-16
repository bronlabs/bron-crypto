package dkg_test

import (
	"crypto/sha256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/keygen/dkg/testutils"
	"github.com/stretchr/testify/require"
	"testing"
)

func Benchmark_Dkg(b *testing.B) {
	curve := k256.NewCurve()
	h := sha256.New
	threshold := 2
	n := 3
	sessionId := []byte("benchmarkSessionId")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, err := testutils.KeyGen(curve, h, threshold, n, nil, sessionId)
		require.NoError(b, err)
	}
}
