package intcom_test

import (
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils"
	"github.com/stretchr/testify/require"
)

func benchmarkCommitting(b *testing.B, keyLen uint) {
	b.Helper()
	trapdoor, err := intcom.SampleTrapdoorKey(keyLen, pcg.NewRandomised())
	require.NoError(b, err)
	message, err := intcom.NewMessage(num.Z().FromInt64(42))
	require.NoError(b, err)

	b.Run(fmt.Sprintf("with commitment key with bit length %d", keyLen), testutils.CommittingBenchmark(b, trapdoor.Export(), message, pcg.NewRandomised()))
	b.Run(fmt.Sprintf("with trapdoor key with bit length %d", keyLen), testutils.CommittingBenchmark(b, trapdoor, message, pcg.NewRandomised()))
}

func BenchmarkCommitting(b *testing.B) {
	for _, keyLen := range []uint{256, 512, 1024, 2048} {
		benchmarkCommitting(b, keyLen)
	}
}
