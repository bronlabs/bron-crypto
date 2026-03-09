package hierarchical_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type hFixture struct {
	name        string
	ac          *hierarchical.HierarchicalConjunctiveThreshold
	qualified   [][]sharing.ID
	unqualified [][]sharing.ID
	allIDs      []sharing.ID
}

func newAC(t *testing.T, levels ...*hierarchical.ThresholdLevel) *hierarchical.HierarchicalConjunctiveThreshold {
	t.Helper()
	ac, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(levels...)
	require.NoError(t, err)
	return ac
}

func formatIDs(ids []sharing.ID) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", id)
	}
	b.WriteByte('}')
	return b.String()
}

// twoLevelFixture: level-0 {1,2,3} threshold=2, level-1 {4,5,6} threshold=4.
func twoLevelFixture(t *testing.T) hFixture {
	t.Helper()
	ac := newAC(t,
		hierarchical.WithLevel(2, 1, 2, 3),
		hierarchical.WithLevel(4, 4, 5, 6),
	)
	return hFixture{
		name: "2-level(2,4)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 4, 5},       // 2 from L0, 2 from L1
			{1, 2, 3, 4},       // 3 from L0, 1 from L1
			{1, 3, 4, 5},       // 2 from L0, 2 from L1
			{2, 3, 5, 6},       // 2 from L0, 2 from L1
			{1, 2, 3, 4, 5, 6}, // everyone
		},
		unqualified: [][]sharing.ID{
			{1, 4, 5},    // only 1 from L0
			{4, 5, 6},    // 0 from L0
			{1, 2, 3},    // only 3 total, need 4
			{1, 2},       // only 2 total
			{1},          // singleton
			{3, 4, 5, 6}, // only 1 from L0
		},
		allIDs: []sharing.ID{1, 2, 3, 4, 5, 6},
	}
}

// threeLevelFixture: L0 {1,2} t=1, L1 {3,4} t=2, L2 {5,6} t=4.
func threeLevelFixture(t *testing.T) hFixture {
	t.Helper()
	ac := newAC(t,
		hierarchical.WithLevel(1, 1, 2),
		hierarchical.WithLevel(2, 3, 4),
		hierarchical.WithLevel(4, 5, 6),
	)
	return hFixture{
		name: "3-level(1,2,4)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 3, 5, 6},    // 1+1+2
			{2, 4, 5, 6},    // 1+1+2
			{1, 2, 3, 4},    // 2+2+0
			{1, 3, 4, 5},    // 1+2+1
			{1, 2, 3, 5, 6}, // 2+1+2
			{1, 2, 3, 4, 5, 6},
		},
		unqualified: [][]sharing.ID{
			{3, 5, 6}, // 0 from L0
			{1, 5, 6}, // only 1 from L0+L1
			{1, 3},    // only 2 total, need 4
			{5, 6},    // 0 from L0
			{1, 2, 5}, // only 3 total, need 4
			{1, 3, 5}, // only 3 total
		},
		allIDs: []sharing.ID{1, 2, 3, 4, 5, 6},
	}
}

// singleLevelFixture: degenerates to threshold {1,2,3,4} t=3.
func singleLevelFixture(t *testing.T) hFixture {
	t.Helper()
	ac := newAC(t,
		hierarchical.WithLevel(3, 1, 2, 3, 4),
	)
	return hFixture{
		name: "1-level(3)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 3},
			{1, 2, 4},
			{1, 3, 4},
			{2, 3, 4},
			{1, 2, 3, 4},
		},
		unqualified: [][]sharing.ID{
			{1, 2},
			{3, 4},
			{1},
		},
		allIDs: []sharing.ID{1, 2, 3, 4},
	}
}

// wideFixture: 2 levels with more shareholders.
// L0 {1,2,3,4} t=2, L1 {5,6,7,8} t=4.
func wideFixture(t *testing.T) hFixture {
	t.Helper()
	ac := newAC(t,
		hierarchical.WithLevel(2, 1, 2, 3, 4),
		hierarchical.WithLevel(4, 5, 6, 7, 8),
	)
	return hFixture{
		name: "wide-2-level(2,4)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 5, 6},
			{3, 4, 7, 8},
			{1, 3, 5, 7},
			{1, 2, 3, 4},
			{1, 2, 3, 5},
			{1, 2, 3, 4, 5, 6, 7, 8},
		},
		unqualified: [][]sharing.ID{
			{1, 5, 6, 7},    // only 1 from L0
			{5, 6, 7, 8},    // 0 from L0
			{1, 2, 3},       // only 3 total
			{1, 5, 6},       // only 1 from L0, 3 total
			{3, 5, 6, 7, 8}, // only 1 from L0
		},
		allIDs: []sharing.ID{1, 2, 3, 4, 5, 6, 7, 8},
	}
}

func allHFixtures(t *testing.T) []hFixture {
	t.Helper()
	return []hFixture{
		twoLevelFixture(t),
		threeLevelFixture(t),
		singleLevelFixture(t),
		wideFixture(t),
	}
}

// ---------------------------------------------------------------------------
// InducedMSP – basic construction
// ---------------------------------------------------------------------------

func TestInducedMSP_Construction(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allHFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			m, err := hierarchical.InducedMSP(field, fx.ac)
			require.NoError(t, err)
			require.NotNil(t, m)
		})
	}
}

// ---------------------------------------------------------------------------
// MSP dimensions match the access structure
// ---------------------------------------------------------------------------

func TestInducedMSP_Dimensions(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allHFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			m, err := hierarchical.InducedMSP(field, fx.ac)
			require.NoError(t, err)

			require.Equal(t, uint(len(fx.allIDs)), m.Size(),
				"MSP should have one row per shareholder")

			thresholds := fx.ac.Thresholds()
			largest := thresholds[len(thresholds)-1]
			require.Equal(t, uint(largest), m.D(),
				"MSP columns should equal the largest cumulative threshold")
		})
	}
}

// ---------------------------------------------------------------------------
// MSP is ideal (each shareholder owns exactly one row)
// ---------------------------------------------------------------------------

func TestInducedMSP_IsIdeal(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allHFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			m, err := hierarchical.InducedMSP(field, fx.ac)
			require.NoError(t, err)
			require.True(t, m.IsIdeal(),
				"hierarchical InducedMSP should assign exactly one row per shareholder")
		})
	}
}

// ---------------------------------------------------------------------------
// MSP row-to-holder mapping matches the access structure shareholders
// ---------------------------------------------------------------------------

func TestInducedMSP_RowMapping(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allHFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			m, err := hierarchical.InducedMSP(field, fx.ac)
			require.NoError(t, err)

			rth := m.RowsToHolders()
			gotIDs := hashset.NewComparable[sharing.ID]()
			for _, id := range rth.Values() {
				gotIDs.Add(id)
			}
			require.True(t, gotIDs.Freeze().Equal(fx.ac.Shareholders()),
				"MSP row labels should cover all shareholders")
		})
	}
}

// ---------------------------------------------------------------------------
// Target vector is the standard unit vector e_0
// ---------------------------------------------------------------------------

func TestInducedMSP_TargetVector(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allHFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			m, err := hierarchical.InducedMSP(field, fx.ac)
			require.NoError(t, err)

			tv := m.TargetVector()
			require.True(t, tv.IsRowVector())
			_, cols := tv.Dimensions()
			for c := range cols {
				v, err := tv.Get(0, c)
				require.NoError(t, err)
				if c == 0 {
					require.True(t, v.IsOne(), "target[0] should be 1")
				} else {
					require.True(t, v.IsZero(), "target[%d] should be 0", c)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MSP.Accepts agrees with HierarchicalConjunctiveThreshold.IsQualified
// ---------------------------------------------------------------------------

func TestInducedMSP_AcceptsMatchesIsQualified(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allHFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			m, err := hierarchical.InducedMSP(field, fx.ac)
			require.NoError(t, err)

			for _, qset := range fx.qualified {
				t.Run("qualified/"+formatIDs(qset), func(t *testing.T) {
					t.Parallel()
					require.True(t, m.Accepts(qset...),
						"MSP should accept qualified set %v", qset)
				})
			}

			for _, uset := range fx.unqualified {
				t.Run("unqualified/"+formatIDs(uset), func(t *testing.T) {
					t.Parallel()
					require.False(t, m.Accepts(uset...),
						"MSP should reject unqualified set %v", uset)
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Exhaustive acceptance/rejection for small access structures
// ---------------------------------------------------------------------------

func TestInducedMSP_ExhaustiveSubsets(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := twoLevelFixture(t)
	m, err := hierarchical.InducedMSP(field, fx.ac)
	require.NoError(t, err)

	for k := uint(1); k <= uint(len(fx.allIDs)); k++ {
		for subset := range sliceutils.Combinations(fx.allIDs, k) {
			expected := fx.ac.IsQualified(subset...)
			got := m.Accepts(subset...)
			require.Equal(t, expected, got,
				"disagreement on subset %v: IsQualified=%v, Accepts=%v",
				subset, expected, got)
		}
	}
}

// ---------------------------------------------------------------------------
// ReconstructionVector succeeds for qualified, fails for unqualified
// ---------------------------------------------------------------------------

func TestInducedMSP_ReconstructionVectorValid(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allHFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			m, err := hierarchical.InducedMSP(field, fx.ac)
			require.NoError(t, err)

			for _, qset := range fx.qualified {
				t.Run(formatIDs(qset), func(t *testing.T) {
					t.Parallel()
					recVec, err := m.ReconstructionVector(qset...)
					require.NoError(t, err)
					require.NotNil(t, recVec)

					rows, cols := recVec.Dimensions()
					require.Equal(t, 1, cols)
					require.Positive(t, rows)
				})
			}
		})
	}
}

func TestInducedMSP_ReconstructionVectorFailsUnqualified(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allHFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			m, err := hierarchical.InducedMSP(field, fx.ac)
			require.NoError(t, err)

			for _, uset := range fx.unqualified {
				t.Run(formatIDs(uset), func(t *testing.T) {
					t.Parallel()
					_, err := m.ReconstructionVector(uset...)
					require.Error(t, err,
						"ReconstructionVector should fail for unqualified set %v", uset)
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Deterministic matrix: InducedMSP produces the same matrix for the same AC
// ---------------------------------------------------------------------------

func TestInducedMSP_DeterministicMatrix(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := twoLevelFixture(t)

	m1, err := hierarchical.InducedMSP(field, fx.ac)
	require.NoError(t, err)
	m2, err := hierarchical.InducedMSP(field, fx.ac)
	require.NoError(t, err)

	require.True(t, m1.Matrix().Equal(m2.Matrix()),
		"InducedMSP should be deterministic for the same access structure")
}

// ---------------------------------------------------------------------------
// Monotonicity: adding more holders to a qualified set keeps it qualified
// ---------------------------------------------------------------------------

func TestInducedMSP_Monotonicity(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allHFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			m, err := hierarchical.InducedMSP(field, fx.ac)
			require.NoError(t, err)

			for _, qset := range fx.qualified {
				qsetSet := hashset.NewComparable(qset...)
				for _, id := range fx.allIDs {
					if qsetSet.Contains(id) {
						continue
					}
					extended := append(slices.Clone(qset), id)
					require.True(t, m.Accepts(extended...),
						"superset of qualified set should also be qualified: %v", extended)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Rank correctness: verify derivative orders from the Rank function.
// ---------------------------------------------------------------------------

func TestInducedMSP_RankConsistency(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := threeLevelFixture(t)
	// 3-level: L0 {1,2} t=1, L1 {3,4} t=2, L2 {5,6} t=4.
	// Expected ranks: L0 -> 0, L1 -> 1, L2 -> 2.

	m, err := hierarchical.InducedMSP(field, fx.ac)
	require.NoError(t, err)

	require.Equal(t, uint(6), m.Size())
	require.Equal(t, uint(4), m.D())

	expectedRanks := map[sharing.ID]int{
		1: 0, 2: 0,
		3: 1, 4: 1,
		5: 2, 6: 2,
	}
	for id, expectedRank := range expectedRanks {
		rank, ok := fx.ac.Rank(id)
		require.True(t, ok, "rank should exist for ID %d", id)
		require.Equal(t, expectedRank, rank, "rank mismatch for ID %d", id)
	}
}

// ---------------------------------------------------------------------------
// BLS12-381 field: verify InducedMSP is field-agnostic
// ---------------------------------------------------------------------------

func TestInducedMSP_BLS12381(t *testing.T) {
	t.Parallel()

	field := bls12381.NewScalarField()
	fx := twoLevelFixture(t)

	m, err := hierarchical.InducedMSP(field, fx.ac)
	require.NoError(t, err)

	for _, qset := range fx.qualified {
		require.True(t, m.Accepts(qset...))
	}
	for _, uset := range fx.unqualified {
		require.False(t, m.Accepts(uset...))
	}
}

// ---------------------------------------------------------------------------
// Birkhoff matrix non-singularity for qualified sets of exact threshold size.
// ---------------------------------------------------------------------------

func TestInducedMSP_QualifiedSubmatrixNonSingular(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allHFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			m, err := hierarchical.InducedMSP(field, fx.ac)
			require.NoError(t, err)

			matrix := m.Matrix()
			d := int(m.D())

			for _, qset := range fx.qualified {
				if len(qset) != d {
					continue
				}

				t.Run(formatIDs(qset), func(t *testing.T) {
					t.Parallel()
					var rowIdxs []int
					for _, id := range qset {
						rowSet, ok := m.HoldersToRows().Get(id)
						require.True(t, ok)
						rowIdxs = append(rowIdxs, rowSet.List()...)
					}
					slices.Sort(rowIdxs)

					sub, err := matrix.SubMatrixGivenRows(rowIdxs...)
					require.NoError(t, err)

					sq, err := sub.AsSquare()
					require.NoError(t, err)
					det := sq.Determinant()
					require.False(t, det.IsZero(),
						"qualified set %v should have non-singular submatrix", qset)
				})
			}
		})
	}
}
