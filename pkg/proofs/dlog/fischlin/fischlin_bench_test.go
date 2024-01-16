package fischlin_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
)

func BenchmarkFischlin(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}
	curve := k256.NewCurve()
	sid := []byte("sid")
	for i := 0; i < b.N; i++ {
		doFischlin(curve, sid, crand.Reader)
	}
}
