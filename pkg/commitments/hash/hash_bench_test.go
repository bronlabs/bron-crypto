package hash_comm_test

import (
	"fmt"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils"
	"github.com/stretchr/testify/require"
)

func BenchmarkCommitting(b *testing.B) {
	key, err := hash_comm.SampleCommitmentKey(pcg.NewRandomised())
	require.NoError(b, err)

	message := hash_comm.Message([]byte("something"))

	b.Run("with commitment key", testutils.CommittingBenchmark(b, key, message, pcg.NewRandomised()))
}

func BenchmarkCommittingBySize(b *testing.B) {
	key, err := hash_comm.SampleCommitmentKey(pcg.NewRandomised())
	require.NoError(b, err)
	prng := pcg.NewRandomised()

	for _, size := range []int{32, 256, 1 << 10, 1 << 14, 1 << 20} {
		msg := make(hash_comm.Message, size)
		_, _ = io.ReadFull(prng, msg)
		b.Run(fmt.Sprintf("msg=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			testutils.CommittingBenchmark(b, key, msg, prng)(b)
		})
	}
}
