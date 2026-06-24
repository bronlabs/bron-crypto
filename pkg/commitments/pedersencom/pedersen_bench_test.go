package pedersencom_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersencom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils"
)

func BenchmarkCommitting(b *testing.B) {
	key, err := pedersencom.SampleCommitmentKey(k256.NewCurve(), pcg.NewRandomised())
	require.NoError(b, err)
	trapdoor, err := pedersencom.SampleTrapdoorKey(k256.NewCurve(), pcg.NewRandomised())
	require.NoError(b, err)
	message, err := pedersencom.NewMessage(k256.NewScalarField().FromUint64(42))
	require.NoError(b, err)

	b.Run("with commitment key", testutils.CommittingBenchmark(b, key, message, pcg.NewRandomised()))
	b.Run("with trapdoor key", testutils.CommittingBenchmark(b, trapdoor, message, pcg.NewRandomised()))
}
