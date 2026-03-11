package boolexpr_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/boolexpr"
)

func TestThresholdGateAccessStructureIsQualified(t *testing.T) {
	t.Parallel()

	as := boolexpr.NewThresholdGateAccessStructure(
		boolexpr.Threshold(2,
			boolexpr.Threshold(2,
				boolexpr.ID(1),
				boolexpr.ID(2),
				boolexpr.ID(3),
			),
			boolexpr.Threshold(2,
				boolexpr.ID(4),
				boolexpr.ID(5),
				boolexpr.ID(6),
			),
			boolexpr.Threshold(2,
				boolexpr.ID(7),
				boolexpr.ID(8),
				boolexpr.ID(9),
			),
		),
	)

	require.Equal(t, 9, as.Shareholders().Size())
	require.True(t, as.IsQualified(1, 2, 5, 6))
	require.False(t, as.IsQualified(1, 2, 3, 4))
}

func TestConvertExampleC(t *testing.T) {
	as := boolexpr.NewThresholdGateAccessStructure(
		boolexpr.Threshold(2,
			boolexpr.Threshold(2,
				boolexpr.ID(1),
				boolexpr.ID(2),
				boolexpr.ID(3)),
			boolexpr.Threshold(2,
				boolexpr.ID(4),
				boolexpr.ID(5),
				boolexpr.ID(6)),
			boolexpr.Threshold(2,
				boolexpr.ID(7),
				boolexpr.ID(8),
				boolexpr.Threshold(3,
					boolexpr.ID(9),
					boolexpr.ID(10),
					boolexpr.ID(11),
					boolexpr.ID(12),
				),
			),
		),
	)

	field := k256.NewScalarField()
	program, err := boolexpr.InducedMSP(field, as)
	require.NoError(t, err)
	require.True(t, program.Size() == 12)
	require.True(t, program.D() == 7)

	t.Run("should match paper example", func(t *testing.T) {
		t.Parallel()

		expectedMCoeffs := []uint64{
			1, 1, 1, 0, 0, 0, 0,
			1, 1, 2, 0, 0, 0, 0,
			1, 1, 3, 0, 0, 0, 0,
			1, 2, 0, 1, 0, 0, 0,
			1, 2, 0, 2, 0, 0, 0,
			1, 2, 0, 3, 0, 0, 0,
			1, 3, 0, 0, 1, 0, 0,
			1, 3, 0, 0, 2, 0, 0,
			1, 3, 0, 0, 3, 1, 1,
			1, 3, 0, 0, 3, 2, 4,
			1, 3, 0, 0, 3, 3, 9,
			1, 3, 0, 0, 3, 4, 16,
		}
		expectedMCoeffsInF := sliceutils.Map(expectedMCoeffs, func(x uint64) *k256.Scalar { return k256.NewScalarField().FromUint64(x) })
		matrices, err := mat.NewMatrixModule(12, 7, k256.NewScalarField())
		require.NoError(t, err)
		expectedM, err := matrices.NewRowMajor(expectedMCoeffsInF...)
		require.NoError(t, err)
		require.True(t, program.Matrix().Equal(expectedM))
	})

	t.Run("access structure matches MSP", func(t *testing.T) {
		t.Parallel()

		for ids := range sliceutils.KCoveringCombinations(as.Shareholders().List(), 1) {
			a := as.IsQualified(ids...)
			b := program.Accepts(ids...)
			require.Equal(t, a, b)
		}
	})
}
