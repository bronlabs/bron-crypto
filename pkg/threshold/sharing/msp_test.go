package sharing_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type F = *k256.Scalar

func field() *k256.ScalarField { return k256.NewScalarField() }

func fe(v uint64) F { return field().FromUint64(v) }

func feRows(rows [][]uint64) [][]F {
	out := make([][]F, len(rows))
	for i, row := range rows {
		out[i] = make([]F, len(row))
		for j, v := range row {
			out[i][j] = fe(v)
		}
	}
	return out
}

func newMat(t *testing.T, rows [][]uint64) *mat.Matrix[F] {
	t.Helper()
	sr := feRows(rows)
	mod, err := mat.NewMatrixModule(uint(len(rows)), uint(len(rows[0])), field())
	require.NoError(t, err)
	m, err := mod.New(sr)
	require.NoError(t, err)
	return m
}

// --- NewMSP constructor ---

func TestNewMSP(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		// Simple 2x2 identity-like MSP: row 0 → party 1, row 1 → party 2
		m := newMat(t, [][]uint64{{1, 0}, {0, 1}})
		psi := map[int]sharing.ID{0: 1, 1: 2}
		msp, err := sharing.NewMSP(m, psi)
		require.NoError(t, err)
		require.NotNil(t, msp)
	})

	t.Run("nil_matrix", func(t *testing.T) {
		t.Parallel()
		_, err := sharing.NewMSP[F](nil, map[int]sharing.ID{0: 1})
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
	})

	t.Run("nil_psi", func(t *testing.T) {
		t.Parallel()
		m := newMat(t, [][]uint64{{1}})
		_, err := sharing.NewMSP(m, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
	})

	t.Run("psi_missing_row", func(t *testing.T) {
		t.Parallel()
		m := newMat(t, [][]uint64{{1, 0}, {0, 1}})
		psi := map[int]sharing.ID{0: 1} // missing row 1
		_, err := sharing.NewMSP(m, psi)
		require.Error(t, err)
	})

	t.Run("psi_extra_row", func(t *testing.T) {
		t.Parallel()
		m := newMat(t, [][]uint64{{1}})
		psi := map[int]sharing.ID{0: 1, 1: 2}
		_, err := sharing.NewMSP(m, psi)
		require.Error(t, err)
	})

	t.Run("psi_zero_id", func(t *testing.T) {
		t.Parallel()
		m := newMat(t, [][]uint64{{1}})
		psi := map[int]sharing.ID{0: 0}
		_, err := sharing.NewMSP(m, psi)
		require.Error(t, err)
	})

	t.Run("psi_negative_index", func(t *testing.T) {
		t.Parallel()
		m := newMat(t, [][]uint64{{1}})
		psi := map[int]sharing.ID{0: 1, -1: 2}
		_, err := sharing.NewMSP(m, psi)
		require.Error(t, err)
	})
}

// --- Accessors ---

func TestMSPAccessors(t *testing.T) {
	t.Parallel()
	m := newMat(t, [][]uint64{{1, 0}, {0, 1}, {1, 1}})
	psi := map[int]sharing.ID{0: 1, 1: 2, 2: 3}
	msp, err := sharing.NewMSP(m, psi)
	require.NoError(t, err)

	t.Run("Matrix", func(t *testing.T) {
		t.Parallel()
		require.True(t, msp.Matrix().Equal(m))
	})

	t.Run("Size", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, 3, msp.Size())
	})

	t.Run("TargetVector", func(t *testing.T) {
		t.Parallel()
		tv := msp.TargetVector()
		r, c := tv.Dimensions()
		require.Equal(t, 1, r)
		require.Equal(t, 2, c) // cols of original matrix
		v0, _ := tv.Get(0, 0)
		v1, _ := tv.Get(0, 1)
		require.True(t, v0.Equal(fe(1)))
		require.True(t, v1.IsZero())
	})

	t.Run("Psi", func(t *testing.T) {
		t.Parallel()
		p := msp.Psi()
		require.Equal(t, 3, p.Size())
		v, ok := p.Get(0)
		require.True(t, ok)
		require.Equal(t, sharing.ID(1), v)
	})
}

// --- Accepts ---

func TestMSPAccepts_Identity(t *testing.T) {
	t.Parallel()

	// Identity matrix: each party owns one row.
	// Target = (1,0) is row 0, so party 1 alone can reconstruct,
	// but party 2 alone cannot (row 1 = (0,1)).
	m := newMat(t, [][]uint64{{1, 0}, {0, 1}})
	psi := map[int]sharing.ID{0: 1, 1: 2}
	msp, err := sharing.NewMSP(m, psi)
	require.NoError(t, err)

	t.Run("both_parties", func(t *testing.T) {
		t.Parallel()
		require.True(t, msp.Accepts(1, 2))
	})

	t.Run("party_1_alone", func(t *testing.T) {
		t.Parallel()
		// Row 0 = (1,0) = target, so party 1 alone suffices.
		require.True(t, msp.Accepts(1))
	})

	t.Run("party_2_alone", func(t *testing.T) {
		t.Parallel()
		// Row 1 = (0,1), cannot produce target (1,0).
		require.False(t, msp.Accepts(2))
	})
}

func TestMSPAccepts_Threshold2of3(t *testing.T) {
	t.Parallel()

	// 2-of-3 threshold MSP over GF(q):
	//   M = [[1, 1],
	//        [1, 2],
	//        [1, 3]]
	// psi: row 0→party 1, row 1→party 2, row 2→party 3
	// Target = (1, 0).
	// Any 2 rows span the target (the Vandermonde-like structure has full column rank
	// for any 2 distinct evaluation points), but a single row cannot.
	m := newMat(t, [][]uint64{{1, 1}, {1, 2}, {1, 3}})
	psi := map[int]sharing.ID{0: 1, 1: 2, 2: 3}
	msp, err := sharing.NewMSP(m, psi)
	require.NoError(t, err)

	t.Run("all_three", func(t *testing.T) {
		t.Parallel()
		require.True(t, msp.Accepts(1, 2, 3))
	})

	t.Run("pair_1_2", func(t *testing.T) {
		t.Parallel()
		require.True(t, msp.Accepts(1, 2))
	})

	t.Run("pair_1_3", func(t *testing.T) {
		t.Parallel()
		require.True(t, msp.Accepts(1, 3))
	})

	t.Run("pair_2_3", func(t *testing.T) {
		t.Parallel()
		require.True(t, msp.Accepts(2, 3))
	})

	t.Run("single_party_1", func(t *testing.T) {
		t.Parallel()
		require.False(t, msp.Accepts(1))
	})

	t.Run("single_party_2", func(t *testing.T) {
		t.Parallel()
		require.False(t, msp.Accepts(2))
	})

	t.Run("single_party_3", func(t *testing.T) {
		t.Parallel()
		require.False(t, msp.Accepts(3))
	})
}

func TestMSPAccepts_MultiRowPerParty(t *testing.T) {
	t.Parallel()

	// Party 1 owns rows 0 and 1, party 2 owns row 2.
	//   M = [[1, 0],
	//        [0, 1],
	//        [1, 1]]
	// Party 1 alone has rows {0,1} = identity → can produce any target.
	// Party 2 alone has row {2} = (1,1) → cannot produce (1,0).
	m := newMat(t, [][]uint64{{1, 0}, {0, 1}, {1, 1}})
	psi := map[int]sharing.ID{0: 1, 1: 1, 2: 2}
	msp, err := sharing.NewMSP(m, psi)
	require.NoError(t, err)

	t.Run("party_1_alone", func(t *testing.T) {
		t.Parallel()
		require.True(t, msp.Accepts(1))
	})

	t.Run("party_2_alone", func(t *testing.T) {
		t.Parallel()
		require.False(t, msp.Accepts(2))
	})

	t.Run("both", func(t *testing.T) {
		t.Parallel()
		require.True(t, msp.Accepts(1, 2))
	})
}

func TestMSPAccepts_UnknownID(t *testing.T) {
	t.Parallel()
	m := newMat(t, [][]uint64{{1, 0}, {0, 1}})
	psi := map[int]sharing.ID{0: 1, 1: 2}
	msp, err := sharing.NewMSP(m, psi)
	require.NoError(t, err)

	require.False(t, msp.Accepts(99))
}

func TestMSPAccepts_EmptyIDs(t *testing.T) {
	t.Parallel()
	m := newMat(t, [][]uint64{{1, 0}, {0, 1}})
	psi := map[int]sharing.ID{0: 1, 1: 2}
	msp, err := sharing.NewMSP(m, psi)
	require.NoError(t, err)

	require.False(t, msp.Accepts())
}

func TestMSPAccepts_SingleColumn(t *testing.T) {
	t.Parallel()

	// 1-column MSP: target = (1). Any non-zero row can reconstruct.
	m := newMat(t, [][]uint64{{1}, {1}, {0}})
	psi := map[int]sharing.ID{0: 1, 1: 2, 2: 3}
	msp, err := sharing.NewMSP(m, psi)
	require.NoError(t, err)

	t.Run("party_with_nonzero_row", func(t *testing.T) {
		t.Parallel()
		require.True(t, msp.Accepts(1))
		require.True(t, msp.Accepts(2))
	})

	t.Run("party_with_zero_row", func(t *testing.T) {
		t.Parallel()
		require.False(t, msp.Accepts(3))
	})

	t.Run("zero_and_nonzero", func(t *testing.T) {
		t.Parallel()
		require.True(t, msp.Accepts(1, 3))
	})
}

func TestMSPAccepts_DuplicateIDs(t *testing.T) {
	t.Parallel()

	// Passing the same ID twice should behave identically to passing it once.
	m := newMat(t, [][]uint64{{1, 1}, {1, 2}, {1, 3}})
	psi := map[int]sharing.ID{0: 1, 1: 2, 2: 3}
	msp, err := sharing.NewMSP(m, psi)
	require.NoError(t, err)

	// Single party cannot reconstruct, even if listed twice.
	require.False(t, msp.Accepts(1, 1))
}

func TestMSPMatrixIsCloned(t *testing.T) {
	t.Parallel()
	m := newMat(t, [][]uint64{{1, 0}, {0, 1}})
	psi := map[int]sharing.ID{0: 1, 1: 2}
	msp, err := sharing.NewMSP(m, psi)
	require.NoError(t, err)

	// Mutate the original matrix and verify MSP is unaffected.
	m.ScalarMulAssign(fe(0))
	require.True(t, m.IsZero())
	require.False(t, msp.Matrix().IsZero())
}
