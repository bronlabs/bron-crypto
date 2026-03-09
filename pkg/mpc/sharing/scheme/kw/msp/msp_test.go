package msp_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
)

var field = k256.NewScalarField()

func scalar(v uint64) *k256.Scalar { return field.FromUint64(v) }

// newMatrix builds an n×m matrix from row-major uint64 values.
func newMatrix(t *testing.T, rows [][]uint64) *mat.Matrix[*k256.Scalar] {
	t.Helper()
	n := len(rows)
	m := len(rows[0])
	mod, err := mat.NewMatrixModule(uint(n), uint(m), field)
	require.NoError(t, err)
	flat := make([]*k256.Scalar, 0, n*m)
	for _, row := range rows {
		for _, v := range row {
			flat = append(flat, scalar(v))
		}
	}
	out, err := mod.NewRowMajor(flat...)
	require.NoError(t, err)
	return out
}

// rowVector builds a 1×m row vector.
func rowVector(t *testing.T, vals ...uint64) *mat.Matrix[*k256.Scalar] {
	t.Helper()
	mod, err := mat.NewMatrixModule(1, uint(len(vals)), field)
	require.NoError(t, err)
	elems := make([]*k256.Scalar, len(vals))
	for i, v := range vals {
		elems[i] = scalar(v)
	}
	out, err := mod.NewRowMajor(elems...)
	require.NoError(t, err)
	return out
}

// --- NewMSP validation tests ---

func TestNewMSP_NilMatrix(t *testing.T) {
	t.Parallel()
	_, err := msp.NewMSP[*k256.Scalar](nil, map[int]msp.ID{0: 1}, rowVector(t, 1))
	require.ErrorIs(t, err, msp.ErrIsNil)
}

func TestNewMSP_NilRowsToHolders(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1}})
	_, err := msp.NewMSP(m, nil, rowVector(t, 1))
	require.ErrorIs(t, err, msp.ErrIsNil)
}

func TestNewMSP_NilTargetVector(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1}})
	_, err := msp.NewMSP[*k256.Scalar](m, map[int]msp.ID{0: 1}, nil)
	require.ErrorIs(t, err, msp.ErrIsNil)
}

func TestNewMSP_TargetNotRowVector(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	// Pass a 2×2 matrix as target instead of a row vector.
	target := newMatrix(t, [][]uint64{{1, 0}, {0, 1}})
	_, err := msp.NewMSP(m, map[int]msp.ID{0: 1, 1: 2}, target)
	require.ErrorIs(t, err, msp.ErrValue)
}

func TestNewMSP_TargetWrongLength(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	target := rowVector(t, 1, 0, 0) // length 3, matrix has 2 columns
	_, err := msp.NewMSP(m, map[int]msp.ID{0: 1, 1: 2}, target)
	require.ErrorIs(t, err, msp.ErrValue)
}

func TestNewMSP_MissingRowIndex(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	target := rowVector(t, 1, 0)
	// Only map row 0, missing row 1.
	_, err := msp.NewMSP(m, map[int]msp.ID{0: 1}, target)
	require.ErrorIs(t, err, msp.ErrValue)
}

func TestNewMSP_ExtraRowIndex(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	target := rowVector(t, 1, 0)
	_, err := msp.NewMSP(m, map[int]msp.ID{0: 1, 1: 2, 5: 3}, target)
	require.ErrorIs(t, err, msp.ErrValue)
}

func TestNewMSP_ZeroIDInMapping(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	target := rowVector(t, 1, 0)
	_, err := msp.NewMSP(m, map[int]msp.ID{0: 0, 1: 2}, target)
	require.ErrorIs(t, err, msp.ErrValue)
}

// --- NewStandardMSP tests ---

func TestNewStandardMSP_NilMatrix(t *testing.T) {
	t.Parallel()
	_, err := msp.NewStandardMSP[*k256.Scalar](nil, map[int]msp.ID{0: 1})
	require.ErrorIs(t, err, msp.ErrIsNil)
}

func TestNewStandardMSP_SetsTargetToE0(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
	sp, err := msp.NewStandardMSP(m, map[int]msp.ID{0: 1, 1: 2})
	require.NoError(t, err)

	tv := sp.TargetVector()
	require.True(t, tv.IsRowVector())
	v0, _ := tv.Get(0, 0)
	v1, _ := tv.Get(0, 1)
	v2, _ := tv.Get(0, 2)
	require.True(t, v0.IsOne())
	require.True(t, v1.IsZero())
	require.True(t, v2.IsZero())
}

// --- Accessor tests ---

func TestMSP_Accessors(t *testing.T) {
	t.Parallel()

	m := newMatrix(t, [][]uint64{
		{1, 0},
		{1, 1},
		{1, 2},
	})
	rth := map[int]msp.ID{0: 10, 1: 20, 2: 30}
	sp, err := msp.NewStandardMSP(m, rth)
	require.NoError(t, err)

	t.Run("Size", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, uint(3), sp.Size())
	})

	t.Run("D", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, uint(2), sp.D())
	})

	t.Run("BaseField", func(t *testing.T) {
		t.Parallel()
		require.NotNil(t, sp.BaseField())
	})

	t.Run("Matrix cloned", func(t *testing.T) {
		t.Parallel()
		// The returned matrix should equal the original but not be the same pointer.
		require.True(t, sp.Matrix().Equal(m))
	})

	t.Run("RowsToHolders", func(t *testing.T) {
		t.Parallel()
		got := sp.RowsToHolders()
		got0, ok0 := got.Get(0)
		got1, ok1 := got.Get(1)
		got2, ok2 := got.Get(2)
		require.True(t, ok0)
		require.True(t, ok1)
		require.True(t, ok2)
		require.Equal(t, msp.ID(10), got0)
		require.Equal(t, msp.ID(20), got1)
		require.Equal(t, msp.ID(30), got2)
	})

	t.Run("HoldersToRows", func(t *testing.T) {
		t.Parallel()
		got := sp.HoldersToRows()
		got10, ok10 := got.Get(10)
		got20, ok20 := got.Get(20)
		got30, ok30 := got.Get(30)
		require.True(t, ok10)
		require.True(t, ok20)
		require.True(t, ok30)
		require.Equal(t, []int{0}, got10.List())
		require.Equal(t, []int{1}, got20.List())
		require.Equal(t, []int{2}, got30.List())
	})

	t.Run("IsIdeal", func(t *testing.T) {
		t.Parallel()
		// Each holder owns exactly one row.
		require.True(t, sp.IsIdeal())
	})
}

func TestMSP_IsIdeal_False(t *testing.T) {
	t.Parallel()

	// Holder 1 owns rows 0 and 1 → not ideal.
	m := newMatrix(t, [][]uint64{{1, 0}, {0, 1}})
	sp, err := msp.NewStandardMSP(m, map[int]msp.ID{0: 1, 1: 1})
	require.NoError(t, err)
	require.False(t, sp.IsIdeal())
}

// --- Accepts / ReconstructionVector tests ---

// Build a simple 2-of-3 threshold MSP manually:
//
//	M = [[1, 1], [1, 2], [1, 3]]   target = (1, 0)
//
// This is a Vandermonde at nodes 1, 2, 3 with 2 columns.
// Any 2 rows span e₀, but no single row does.
func new2of3MSP(t *testing.T) *msp.MSP[*k256.Scalar] {
	t.Helper()
	m := newMatrix(t, [][]uint64{
		{1, 1},
		{1, 2},
		{1, 3},
	})
	sp, err := msp.NewStandardMSP(m, map[int]msp.ID{0: 1, 1: 2, 2: 3})
	require.NoError(t, err)
	return sp
}

func TestMSP_Accepts_QualifiedSets(t *testing.T) {
	t.Parallel()
	sp := new2of3MSP(t)

	qualified := [][]msp.ID{
		{1, 2},
		{1, 3},
		{2, 3},
		{1, 2, 3},
	}
	for _, ids := range qualified {
		require.True(t, sp.Accepts(ids...), "should accept %v", ids)
	}
}

func TestMSP_Accepts_UnqualifiedSets(t *testing.T) {
	t.Parallel()
	sp := new2of3MSP(t)

	unqualified := [][]msp.ID{
		{1},
		{2},
		{3},
	}
	for _, ids := range unqualified {
		require.False(t, sp.Accepts(ids...), "should reject %v", ids)
	}
}

func TestMSP_ReconstructionVector_Success(t *testing.T) {
	t.Parallel()
	sp := new2of3MSP(t)

	recVec, err := sp.ReconstructionVector(1, 2)
	require.NoError(t, err)
	require.NotNil(t, recVec)

	rows, cols := recVec.Dimensions()
	require.Equal(t, 2, rows, "one coefficient per selected row")
	require.Equal(t, 1, cols)
}

func TestMSP_ReconstructionVector_UnknownID(t *testing.T) {
	t.Parallel()
	sp := new2of3MSP(t)

	_, err := sp.ReconstructionVector(1, 99)
	require.Error(t, err)
	require.ErrorIs(t, err, msp.ErrValue)
}

func TestMSP_ReconstructionVector_EmptyIDs(t *testing.T) {
	t.Parallel()
	sp := new2of3MSP(t)

	_, err := sp.ReconstructionVector()
	require.Error(t, err)
	require.ErrorIs(t, err, msp.ErrValue)
}

func TestMSP_ReconstructionVector_InsufficientRows(t *testing.T) {
	t.Parallel()
	sp := new2of3MSP(t)

	// Single row cannot span target.
	_, err := sp.ReconstructionVector(1)
	require.Error(t, err)
}

// --- Multi-row holder tests ---

func TestMSP_MultiRowHolder(t *testing.T) {
	t.Parallel()

	// 2×2 identity matrix: holder 1 owns both rows.
	// With both rows the target (1,0) is trivially in span.
	m := newMatrix(t, [][]uint64{{1, 0}, {0, 1}})
	sp, err := msp.NewStandardMSP(m, map[int]msp.ID{0: 1, 1: 1})
	require.NoError(t, err)

	require.True(t, sp.Accepts(1))
	require.Equal(t, uint(2), sp.Size())
	require.Equal(t, uint(2), sp.D())

	htr := sp.HoldersToRows()
	got1, ok1 := htr.Get(1)
	require.True(t, ok1)
	require.Len(t, got1.List(), 2)
}

// --- Custom target vector tests ---

func TestMSP_CustomTarget(t *testing.T) {
	t.Parallel()

	// M = [[1, 0], [0, 1], [1, 1]]  target = (0, 1)
	// Row 1 alone spans (0,1). Rows 0 and 2 also span it: (0,1) = -1*(1,0) + 1*(1,1).
	m := newMatrix(t, [][]uint64{{1, 0}, {0, 1}, {1, 1}})
	target := rowVector(t, 0, 1)
	sp, err := msp.NewMSP(m, map[int]msp.ID{0: 1, 1: 2, 2: 3}, target)
	require.NoError(t, err)

	require.True(t, sp.Accepts(2), "row 1 alone spans (0,1)")
	require.True(t, sp.Accepts(1, 3), "rows 0 and 2 span (0,1)")
	require.False(t, sp.Accepts(1), "row 0 = (1,0) cannot span (0,1)")
}

func TestMSP_DuplicateIDsDeduped(t *testing.T) {
	t.Parallel()
	sp := new2of3MSP(t)

	// Passing the same ID twice should behave as passing it once.
	require.False(t, sp.Accepts(1, 1), "duplicate of single holder should not qualify")
	require.True(t, sp.Accepts(1, 2, 2), "duplicates should be ignored, {1,2} qualifies")
}
