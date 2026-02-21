package mat_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/mat"
)

// --- Matrix CBOR ---

func TestMatrixCBOR(t *testing.T) {
	t.Parallel()

	t.Run("roundtrip_2x3", func(t *testing.T) {
		t.Parallel()
		orig := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)
		require.NotEmpty(t, data)

		var recovered mat.Matrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))
		require.True(t, orig.Equal(&recovered))
	})

	t.Run("roundtrip_1x1", func(t *testing.T) {
		t.Parallel()
		orig := newMatrix(t, [][]uint64{{42}})
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)

		var recovered mat.Matrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))
		require.True(t, orig.Equal(&recovered))
	})

	t.Run("roundtrip_3x1", func(t *testing.T) {
		t.Parallel()
		orig := newMatrix(t, [][]uint64{{7}, {8}, {9}})
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)

		var recovered mat.Matrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))
		require.True(t, orig.Equal(&recovered))
	})

	t.Run("preserves_dimensions", func(t *testing.T) {
		t.Parallel()
		orig := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)

		var recovered mat.Matrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))
		r, c := recovered.Dimensions()
		require.Equal(t, 2, r)
		require.Equal(t, 3, c)
	})

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		data1, err := m.MarshalCBOR()
		require.NoError(t, err)
		data2, err := m.MarshalCBOR()
		require.NoError(t, err)
		require.Equal(t, data1, data2)
	})

	t.Run("operations_after_unmarshal", func(t *testing.T) {
		t.Parallel()
		orig := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)

		var recovered mat.Matrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))

		doubled := recovered.Double()
		require.True(t, doubled.Equal(newMatrix(t, [][]uint64{{2, 4}, {6, 8}})))
	})

	t.Run("invalid_cbor", func(t *testing.T) {
		t.Parallel()
		var m mat.Matrix[S]
		require.Error(t, m.UnmarshalCBOR([]byte{0xff, 0xfe}))
	})

	t.Run("empty_data", func(t *testing.T) {
		t.Parallel()
		var m mat.Matrix[S]
		require.Error(t, m.UnmarshalCBOR([]byte{}))
	})
}

// --- SquareMatrix CBOR ---

func TestSquareMatrixCBOR(t *testing.T) {
	t.Parallel()

	t.Run("roundtrip_2x2", func(t *testing.T) {
		t.Parallel()
		orig := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)
		require.NotEmpty(t, data)

		var recovered mat.SquareMatrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))
		require.True(t, orig.Equal(&recovered))
	})

	t.Run("roundtrip_1x1", func(t *testing.T) {
		t.Parallel()
		orig := newSquare(t, [][]uint64{{42}})
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)

		var recovered mat.SquareMatrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))
		require.True(t, orig.Equal(&recovered))
	})

	t.Run("roundtrip_3x3", func(t *testing.T) {
		t.Parallel()
		orig := newSquare(t, [][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}})
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)

		var recovered mat.SquareMatrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))
		require.True(t, orig.Equal(&recovered))
	})

	t.Run("roundtrip_identity", func(t *testing.T) {
		t.Parallel()
		orig := identity(t, 3)
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)

		var recovered mat.SquareMatrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))
		require.True(t, recovered.IsIdentity())
	})

	t.Run("preserves_dimension", func(t *testing.T) {
		t.Parallel()
		orig := newSquare(t, [][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}})
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)

		var recovered mat.SquareMatrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))
		require.Equal(t, 3, recovered.N())
	})

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		data1, err := m.MarshalCBOR()
		require.NoError(t, err)
		data2, err := m.MarshalCBOR()
		require.NoError(t, err)
		require.Equal(t, data1, data2)
	})

	t.Run("operations_after_unmarshal", func(t *testing.T) {
		t.Parallel()
		orig := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		data, err := orig.MarshalCBOR()
		require.NoError(t, err)

		var recovered mat.SquareMatrix[S]
		require.NoError(t, recovered.UnmarshalCBOR(data))

		// Verify multiplication works on deserialized matrix.
		product := recovered.Mul(identity(t, 2))
		require.True(t, product.Equal(orig))
	})

	t.Run("invalid_cbor", func(t *testing.T) {
		t.Parallel()
		var m mat.SquareMatrix[S]
		require.Error(t, m.UnmarshalCBOR([]byte{0xff, 0xfe}))
	})

	t.Run("empty_data", func(t *testing.T) {
		t.Parallel()
		var m mat.SquareMatrix[S]
		require.Error(t, m.UnmarshalCBOR([]byte{}))
	})
}
