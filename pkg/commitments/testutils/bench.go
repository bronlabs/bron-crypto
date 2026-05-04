package testutils

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/stretchr/testify/require"
)

func CommittingBenchmark[
	K commitments.CommitmentKey[K, M, W, C], M commitments.Message, W commitments.Witness, C commitments.Commitment[C],
](b *testing.B, key K, message M, prng io.Reader) func(*testing.B) {
	return func(b *testing.B) {
		b.Helper()
		witness, err := key.SampleWitness(prng)
		require.NoError(b, err)
		for b.Loop() {
			_, _ = key.CommitWithWitness(message, witness)
		}
	}
}
