//nolint:testpackage // to access computeJoyeParams
package nt

import (
	crand "crypto/rand"
	"fmt"
	"testing"
)

// Benchmark_ComputeJoyeParams measures the cost of the (uncached) setup pass
// for the Joye-Paillier safe-prime generator. The function is called directly
// to avoid hitting joyeParamsCache.
func Benchmark_ComputeJoyeParams(b *testing.B) {
	for _, bits := range []uint{1024, 1536, 2048} {
		b.Run(fmt.Sprintf("%d-bit", bits), func(b *testing.B) {
			var nPi int
			for b.Loop() {
				p, err := computeJoyeParams(bits, crand.Reader)
				if err != nil {
					b.Fatalf("computeJoyeParams(%d): %v", bits, err)
				}
				nPi = p.nPi
			}
			b.ReportMetric(float64(nPi), "nPi")
		})
	}
}
