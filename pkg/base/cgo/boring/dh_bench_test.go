//go:build !purego && !nobignum

package boring_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
)

func Benchmark_DhGen1024(b *testing.B) {
	const bits = 1024

	for i := 0; i < b.N; i++ {
		dh, err := boring.NewDiffieHellmanGroup().GenerateParameters(bits)
		if err != nil {
			b.Fatal(err)
		}
		_, err = dh.GetP()
		if err != nil {
			b.Fatal(err)
		}
	}
}
