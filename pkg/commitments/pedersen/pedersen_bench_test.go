package pedersen_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils"
	"github.com/stretchr/testify/require"
)

func BenchmarkCommittingWithCommitmentKey(b *testing.B) {
	key, err := pedersen.SampleCommitmentKey(k256.NewCurve(), pcg.NewRandomised())
	require.NoError(b, err)
	trapdoor, err := pedersen.SampleTrapdoorKey(k256.NewCurve(), pcg.NewRandomised())
	require.NoError(b, err)
	message, err := pedersen.NewMessage(k256.NewScalarField().FromUint64(42))
	require.NoError(b, err)

	b.Run("with commitment key", testutils.CommittingBenchmark(b, key, message, pcg.NewRandomised()))
	b.Run("with trapdoor key", testutils.CommittingBenchmark(b, trapdoor, message, pcg.NewRandomised()))
}
