//go:build !purego && !nobignum

package boring_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
)

func Benchmark_DhGen1024(b *testing.B) {
	const bits = 1024

	for i := 0; i < b.N; i++ {
		_ = boring.NewDiffieHellmanGroup().GenerateParameters(bits).GetP()
	}
}
