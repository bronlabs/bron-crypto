package boolexpr_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/boolexpr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	sharinginternal "github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

func TestThresholdGateAccessStructureIsQualified(t *testing.T) {
	t.Parallel()

	as, err := boolexpr.NewThresholdGateAccessStructure(
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
	require.NoError(t, err)
	require.Equal(t, 9, as.Shareholders().Size())
	require.True(t, as.IsQualified(1, 2, 5, 6))
	require.False(t, as.IsQualified(1, 2, 3, 4))
}

// test against example from the paper (section C, page 22)
func TestConvertExampleC(t *testing.T) {
	t.Parallel()

	as, err := boolexpr.NewThresholdGateAccessStructure(
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
	require.NoError(t, err)

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

	t.Run("should share and reconstruct", func(t *testing.T) {
		t.Parallel()

		prng := pcg.NewRandomised()
		scheme, err := kw.NewScheme(field, as)
		require.NoError(t, err)

		secretValue, err := field.Random(prng)
		require.NoError(t, err)
		dealerOutput, err := scheme.Deal(kw.NewSecret(secretValue), prng)
		require.NoError(t, err)

		// check all possibilities
		for ids := range sliceutils.KCoveringCombinations(as.Shareholders().List(), 1) {
			shares := make([]*kw.Share[*k256.Scalar], 0, len(ids))
			for _, id := range ids {
				share, ok := dealerOutput.Shares().Get(id)
				require.True(t, ok)
				shares = append(shares, share)
			}

			reconstructed, err := scheme.Reconstruct(shares...)
			if as.IsQualified(ids...) {
				require.NoError(t, err)
				require.True(t, reconstructed.Value().Equal(secretValue))
			} else {
				require.Error(t, err)
			}
		}
	})

	t.Run("should convert to additive", func(t *testing.T) {
		t.Parallel()

		prng := pcg.NewRandomised()
		scheme, err := kw.NewScheme(field, as)
		require.NoError(t, err)

		secretValue, err := field.Random(prng)
		require.NoError(t, err)
		dealerOutput, err := scheme.Deal(kw.NewSecret(secretValue), prng)
		require.NoError(t, err)

		// check all possibilities
		for ids := range sliceutils.KCoveringCombinations(as.Shareholders().List(), 1) {
			if !as.IsQualified(ids...) {
				continue
			}

			sum := k256.NewScalarField().Zero()
			quorum, err := unanimity.NewUnanimityAccessStructure(hashset.NewComparable(ids...).Freeze())
			require.NoError(t, err)
			for _, id := range ids {
				share, ok := dealerOutput.Shares().Get(id)
				require.True(t, ok)
				additiveShare, err := scheme.ConvertShareToAdditive(share, quorum)
				require.NoError(t, err)
				sum = sum.Add(additiveShare.Value())
			}
			require.True(t, secretValue.Equal(sum))
		}
	})
}

func TestThresholdGateAccessStructureMaximalUnqualifiedSetsIter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		root *boolexpr.Node
	}{
		{
			name: "5-shareholders",
			root: boolexpr.Threshold(2,
				boolexpr.And(
					boolexpr.ID(1),
					boolexpr.ID(2),
				),
				boolexpr.ID(3),
				boolexpr.Threshold(2,
					boolexpr.ID(4),
					boolexpr.ID(5),
				),
			),
		},
		{
			name: "10-shareholders",
			root: boolexpr.Threshold(2,
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
					boolexpr.ID(10),
				),
			),
		},
		{
			name: "15-shareholders",
			root: boolexpr.Threshold(2,
				boolexpr.Threshold(3,
					boolexpr.ID(1),
					boolexpr.ID(2),
					boolexpr.ID(3),
					boolexpr.ID(4),
					boolexpr.ID(5),
				),
				boolexpr.Threshold(3,
					boolexpr.ID(6),
					boolexpr.ID(7),
					boolexpr.ID(8),
					boolexpr.ID(9),
					boolexpr.ID(10),
				),
				boolexpr.Threshold(4,
					boolexpr.ID(11),
					boolexpr.ID(12),
					boolexpr.ID(13),
					boolexpr.ID(14),
					boolexpr.ID(15),
				),
			),
		},
		{
			name: "20-shareholders-deep",
			root: boolexpr.Threshold(2,
				boolexpr.And(
					boolexpr.Or(
						boolexpr.ID(1),
						boolexpr.ID(2),
					),
					boolexpr.Threshold(2,
						boolexpr.ID(3),
						boolexpr.ID(4),
						boolexpr.ID(5),
					),
				),
				boolexpr.Threshold(2,
					boolexpr.And(
						boolexpr.ID(6),
						boolexpr.Or(
							boolexpr.ID(7),
							boolexpr.ID(8),
							boolexpr.ID(9),
						),
					),
					boolexpr.Threshold(2,
						boolexpr.ID(10),
						boolexpr.ID(11),
						boolexpr.ID(12),
					),
					boolexpr.And(
						boolexpr.ID(13),
						boolexpr.ID(14),
					),
				),
				boolexpr.Threshold(2,
					boolexpr.Threshold(2,
						boolexpr.ID(15),
						boolexpr.ID(16),
						boolexpr.ID(17),
					),
					boolexpr.And(
						boolexpr.ID(18),
						boolexpr.Or(
							boolexpr.ID(19),
							boolexpr.ID(20),
						),
					),
				),
			),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			as, err := boolexpr.NewThresholdGateAccessStructure(tc.root)
			require.NoError(t, err)

			maxUnqualifiedSets := slices.Collect(as.MaximalUnqualifiedSetsIter())
			require.Equal(t, referenceBoolexprMaximalUnqualifiedSets(as), canonicalBoolexprSetMap(maxUnqualifiedSets))

			shareholders := as.Shareholders()
			for _, subset := range maxUnqualifiedSets {
				require.True(t, subset.IsSubSet(shareholders))
				require.False(t, as.IsQualified(subset.List()...))

				for id := range shareholders.Iter() {
					if subset.Contains(id) {
						continue
					}

					extended := subset.Unfreeze()
					extended.Add(id)
					require.True(t, as.IsQualified(extended.List()...))
				}
			}
		})
	}
}

func referenceBoolexprMaximalUnqualifiedSets(as *boolexpr.ThresholdGateAccessStructure) map[string]struct{} {
	shareholders := as.Shareholders().List()
	slices.Sort(shareholders)

	out := make(map[string]struct{})
	for size := 0; size <= len(shareholders); size++ {
		for combo := range sliceutils.Combinations(shareholders, uint(size)) {
			subset := hashset.NewComparable(combo...).Freeze()
			if as.IsQualified(combo...) {
				continue
			}

			maximal := true
			for _, id := range shareholders {
				if subset.Contains(id) {
					continue
				}

				extended := subset.Unfreeze()
				extended.Add(id)
				if !as.IsQualified(extended.List()...) {
					maximal = false
					break
				}
			}
			if maximal {
				out[canonicalBoolexprIDs(subset)] = struct{}{}
			}
		}
	}

	return out
}

func canonicalBoolexprSetMap(sets []ds.Set[sharinginternal.ID]) map[string]struct{} {
	out := make(map[string]struct{}, len(sets))
	for _, subset := range sets {
		out[canonicalBoolexprIDs(subset)] = struct{}{}
	}
	return out
}

func canonicalBoolexprIDs(s ds.Set[sharinginternal.ID]) string {
	ids := s.List()
	slices.Sort(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprint(id))
	}
	return strings.Join(parts, ",")
}

// TestThresholdGateChildOrderChangesMSP shows that boolexpr.Threshold is order-
// dependent: two trees that encode the same monotone access structure but pass
// children in different orders induce different MSPs, even though IsQualified
// agrees on every coalition.
func TestThresholdGateChildOrderChangesMSP(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	t.Run("permuted leaves at a flat gate change rho but not matrix entries", func(t *testing.T) {
		t.Parallel()

		asForward, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Threshold(2,
				boolexpr.ID(1),
				boolexpr.ID(2),
				boolexpr.ID(3),
			),
		)
		require.NoError(t, err)

		asReversed, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Threshold(2,
				boolexpr.ID(3),
				boolexpr.ID(2),
				boolexpr.ID(1),
			),
		)
		require.NoError(t, err)

		for ids := range sliceutils.KCoveringCombinations(asForward.Shareholders().List(), 1) {
			require.Equal(t, asForward.IsQualified(ids...), asReversed.IsQualified(ids...))
		}

		mspForward, err := boolexpr.InducedMSP(field, asForward)
		require.NoError(t, err)
		mspReversed, err := boolexpr.InducedMSP(field, asReversed)
		require.NoError(t, err)

		require.True(t, mspForward.Matrix().Equal(mspReversed.Matrix()),
			"matrix entries should match when only flat-gate leaves are permuted")
		require.False(t, mspForward.Equal(mspReversed),
			"row-to-holder mapping must differ when leaves are permuted")

		rowsForward := mspForward.RowsToHolders()
		rowsReversed := mspReversed.RowsToHolders()
		idAtRow0Forward, ok := rowsForward.Get(0)
		require.True(t, ok)
		require.Equal(t, sharinginternal.ID(1), idAtRow0Forward)
		idAtRow0Reversed, ok := rowsReversed.Get(0)
		require.True(t, ok)
		require.Equal(t, sharinginternal.ID(3), idAtRow0Reversed)
	})

	t.Run("moving a sub-gate changes matrix entries", func(t *testing.T) {
		t.Parallel()

		asSubgateFirst, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Threshold(2,
				boolexpr.Threshold(2, boolexpr.ID(1), boolexpr.ID(2)),
				boolexpr.ID(3),
			),
		)
		require.NoError(t, err)

		asSubgateLast, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Threshold(2,
				boolexpr.ID(3),
				boolexpr.Threshold(2, boolexpr.ID(1), boolexpr.ID(2)),
			),
		)
		require.NoError(t, err)

		for ids := range sliceutils.KCoveringCombinations(asSubgateFirst.Shareholders().List(), 1) {
			require.Equal(t, asSubgateFirst.IsQualified(ids...), asSubgateLast.IsQualified(ids...))
		}

		mspSubgateFirst, err := boolexpr.InducedMSP(field, asSubgateFirst)
		require.NoError(t, err)
		mspSubgateLast, err := boolexpr.InducedMSP(field, asSubgateLast)
		require.NoError(t, err)

		require.False(t, mspSubgateFirst.Matrix().Equal(mspSubgateLast.Matrix()),
			"matrix entries must differ when a sub-gate's position at its parent changes")
		require.False(t, mspSubgateFirst.Equal(mspSubgateLast))
	})
}
