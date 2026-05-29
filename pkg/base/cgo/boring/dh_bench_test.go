//go:build !purego && !nobignum

package boring_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/stretchr/testify/require"
)

func Benchmark_DhGen1024(b *testing.B) {
	const bits = 1024

	for b.Loop() {
		dh, err := boring.NewDiffieHellmanGroup().GenerateParameters(bits)
		require.NoError(b, err)
		_, err = dh.GetP()
		require.NoError(b, err)
	}
}
