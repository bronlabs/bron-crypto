//go:build !purego && !nobignum

package boring_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/stretchr/testify/require"
)

func Benchmark_GenSafePrime1024(b *testing.B) {
	const bits = 1024

	for b.Loop() {
		bn := boring.NewBigNum()

		_, err := bn.GenPrime(bits, ct.True)
		require.NoError(b, err)
	}
}
