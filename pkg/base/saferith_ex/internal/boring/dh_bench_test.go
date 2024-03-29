package boring_test

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex/internal/boring"
)

func Benchmark_DhGen1024(b *testing.B) {
	const bits = 1024

	for i := 0; i < b.N; i++ {
		_ = boring.NewDiffieHellmanGroup().GenerateParameters(bits).GetP()
	}
}
