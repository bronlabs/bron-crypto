package vandermonde_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/vandermonde"
)

var field = k256.NewScalarField()

func scalar(v uint64) *k256.Scalar { return field.FromUint64(v) }

func TestBuildVandermondeMatrix(t *testing.T) {
	t.Parallel()

	t.Run("1x1", func(t *testing.T) {
		t.Parallel()
		m, err := vandermonde.BuildVandermondeMatrix([]*k256.Scalar{scalar(5)}, 1)
		require.NoError(t, err)
		r, c := m.Dimensions()
		require.Equal(t, 1, r)
		require.Equal(t, 1, c)
		v, _ := m.Get(0, 0)
		require.True(t, v.IsOne(), "x^0 should be 1")
	})

	t.Run("2x2", func(t *testing.T) {
		t.Parallel()
		// nodes = [2, 3]
		// V = [[1, 2], [1, 3]]
		m, err := vandermonde.BuildVandermondeMatrix([]*k256.Scalar{scalar(2), scalar(3)}, 2)
		require.NoError(t, err)
		r, c := m.Dimensions()
		require.Equal(t, 2, r)
		require.Equal(t, 2, c)

		v00, _ := m.Get(0, 0)
		v01, _ := m.Get(0, 1)
		v10, _ := m.Get(1, 0)
		v11, _ := m.Get(1, 1)
		require.True(t, v00.Equal(scalar(1)))
		require.True(t, v01.Equal(scalar(2)))
		require.True(t, v10.Equal(scalar(1)))
		require.True(t, v11.Equal(scalar(3)))
	})

	t.Run("3x3", func(t *testing.T) {
		t.Parallel()
		// nodes = [2, 3, 5]
		// V = [[1, 2, 4], [1, 3, 9], [1, 5, 25]]
		m, err := vandermonde.BuildVandermondeMatrix([]*k256.Scalar{scalar(2), scalar(3), scalar(5)}, 3)
		require.NoError(t, err)
		r, c := m.Dimensions()
		require.Equal(t, 3, r)
		require.Equal(t, 3, c)

		expected := [][]uint64{
			{1, 2, 4},
			{1, 3, 9},
			{1, 5, 25},
		}
		for i, row := range expected {
			for j, want := range row {
				v, _ := m.Get(i, j)
				require.True(t, v.Equal(scalar(want)), "entry (%d,%d): got %v, want %d", i, j, v, want)
			}
		}
	})

	t.Run("first_column_all_ones", func(t *testing.T) {
		t.Parallel()
		nodes := []*k256.Scalar{scalar(7), scalar(11), scalar(13), scalar(17)}
		m, err := vandermonde.BuildVandermondeMatrix(nodes, uint(len(nodes)))
		require.NoError(t, err)
		for i := range 4 {
			v, _ := m.Get(i, 0)
			require.True(t, v.IsOne(), "column 0, row %d should be 1", i)
		}
	})

	t.Run("second_column_equals_nodes", func(t *testing.T) {
		t.Parallel()
		nodes := []*k256.Scalar{scalar(7), scalar(11), scalar(13)}
		m, err := vandermonde.BuildVandermondeMatrix(nodes, uint(len(nodes)))
		require.NoError(t, err)
		for i, node := range nodes {
			v, _ := m.Get(i, 1)
			require.True(t, v.Equal(node), "column 1, row %d should equal node", i)
		}
	})

	t.Run("node_zero", func(t *testing.T) {
		t.Parallel()
		// node=0: row = [1, 0, 0, ...]
		m, err := vandermonde.BuildVandermondeMatrix([]*k256.Scalar{scalar(0), scalar(1), scalar(2)}, 3)
		require.NoError(t, err)
		v00, _ := m.Get(0, 0)
		v01, _ := m.Get(0, 1)
		v02, _ := m.Get(0, 2)
		require.True(t, v00.IsOne())
		require.True(t, v01.IsZero())
		require.True(t, v02.IsZero())
	})

	t.Run("empty_nodes", func(t *testing.T) {
		t.Parallel()
		_, err := vandermonde.BuildVandermondeMatrix([]*k256.Scalar{}, 1)
		require.Error(t, err)
	})

	t.Run("zero_cols", func(t *testing.T) {
		t.Parallel()
		_, err := vandermonde.BuildVandermondeMatrix([]*k256.Scalar{scalar(1)}, 0)
		require.Error(t, err)
	})

	t.Run("rectangular_3x2", func(t *testing.T) {
		t.Parallel()
		// nodes = [2, 3, 5], cols = 2
		// V = [[1, 2], [1, 3], [1, 5]]
		m, err := vandermonde.BuildVandermondeMatrix([]*k256.Scalar{scalar(2), scalar(3), scalar(5)}, 2)
		require.NoError(t, err)
		r, c := m.Dimensions()
		require.Equal(t, 3, r)
		require.Equal(t, 2, c)

		expected := [][]uint64{
			{1, 2},
			{1, 3},
			{1, 5},
		}
		for i, row := range expected {
			for j, want := range row {
				v, _ := m.Get(i, j)
				require.True(t, v.Equal(scalar(want)), "entry (%d,%d): got %v, want %d", i, j, v, want)
			}
		}
	})

	t.Run("rectangular_4x3", func(t *testing.T) {
		t.Parallel()
		// nodes = [1, 2, 3, 4], cols = 3
		// V = [[1,1,1], [1,2,4], [1,3,9], [1,4,16]]
		nodes := []*k256.Scalar{scalar(1), scalar(2), scalar(3), scalar(4)}
		m, err := vandermonde.BuildVandermondeMatrix(nodes, 3)
		require.NoError(t, err)
		r, c := m.Dimensions()
		require.Equal(t, 4, r)
		require.Equal(t, 3, c)

		expected := [][]uint64{
			{1, 1, 1},
			{1, 2, 4},
			{1, 3, 9},
			{1, 4, 16},
		}
		for i, row := range expected {
			for j, want := range row {
				v, _ := m.Get(i, j)
				require.True(t, v.Equal(scalar(want)), "entry (%d,%d): got %v, want %d", i, j, v, want)
			}
		}
	})
}

func TestInterpolate(t *testing.T) {
	t.Parallel()

	t.Run("constant_polynomial", func(t *testing.T) {
		t.Parallel()
		// f(x) = 7
		nodes := []*k256.Scalar{scalar(1), scalar(2), scalar(3)}
		values := []*k256.Scalar{scalar(7), scalar(7), scalar(7)}

		poly, err := vandermonde.Interpolate(nodes, values, scalar(0))
		require.NoError(t, err)
		require.True(t, poly.Eval(scalar(99)).Equal(scalar(7)))
	})

	t.Run("linear_polynomial", func(t *testing.T) {
		t.Parallel()
		// f(x) = 2x + 1: (0,1), (1,3)
		nodes := []*k256.Scalar{scalar(0), scalar(1)}
		values := []*k256.Scalar{scalar(1), scalar(3)}

		poly, err := vandermonde.Interpolate(nodes, values, scalar(0))
		require.NoError(t, err)
		// f(5) = 11
		require.True(t, poly.Eval(scalar(5)).Equal(scalar(11)))
	})

	t.Run("quadratic_polynomial", func(t *testing.T) {
		t.Parallel()
		// f(x) = x^2: (0,0), (1,1), (2,4)
		nodes := []*k256.Scalar{scalar(0), scalar(1), scalar(2)}
		values := []*k256.Scalar{scalar(0), scalar(1), scalar(4)}

		poly, err := vandermonde.Interpolate(nodes, values, scalar(0))
		require.NoError(t, err)
		require.True(t, poly.Eval(scalar(5)).Equal(scalar(25)))
		require.True(t, poly.Eval(scalar(10)).Equal(scalar(100)))
	})

	t.Run("passes_through_given_points", func(t *testing.T) {
		t.Parallel()
		nodes := []*k256.Scalar{scalar(2), scalar(5), scalar(9)}
		values := []*k256.Scalar{scalar(17), scalar(42), scalar(3)}

		poly, err := vandermonde.Interpolate(nodes, values, scalar(0))
		require.NoError(t, err)
		for i, node := range nodes {
			require.True(t, poly.Eval(node).Equal(values[i]), "polynomial should pass through point %d", i)
		}
	})

	t.Run("secret_sharing_reconstruction", func(t *testing.T) {
		t.Parallel()
		polyRing, err := polynomials.NewPolynomialRing(field)
		require.NoError(t, err)

		// p(x) = 42 + 7x + 3x^2, secret = p(0) = 42
		secret := scalar(42)
		original, err := polyRing.New(secret.Clone(), scalar(7), scalar(3))
		require.NoError(t, err)

		nodes := []*k256.Scalar{scalar(1), scalar(2), scalar(3)}
		values := make([]*k256.Scalar, len(nodes))
		for i, n := range nodes {
			values[i] = original.Eval(n)
		}

		poly, err := vandermonde.Interpolate(nodes, values, field.Zero())
		require.NoError(t, err)
		require.True(t, poly.Eval(field.Zero()).Equal(secret))
	})

	t.Run("agrees_with_lagrange", func(t *testing.T) {
		t.Parallel()
		nodes := []*k256.Scalar{scalar(1), scalar(3), scalar(7)}
		values := []*k256.Scalar{scalar(10), scalar(20), scalar(30)}
		at := scalar(5)

		lagrangeResult, err := lagrange.InterpolateAt(nodes, values, at.Clone())
		require.NoError(t, err)

		poly, err := vandermonde.Interpolate(nodes, values, at.Clone())
		require.NoError(t, err)

		require.True(t, poly.Eval(at).Equal(lagrangeResult))
	})

	t.Run("length_mismatch", func(t *testing.T) {
		t.Parallel()
		_, err := vandermonde.Interpolate(
			[]*k256.Scalar{scalar(1), scalar(2)},
			[]*k256.Scalar{scalar(1)},
			scalar(0),
		)
		require.Error(t, err)
	})

	t.Run("duplicate_nodes_inconsistent", func(t *testing.T) {
		t.Parallel()
		// Duplicate nodes with different values make the system inconsistent.
		_, err := vandermonde.Interpolate(
			[]*k256.Scalar{scalar(1), scalar(1)},
			[]*k256.Scalar{scalar(5), scalar(6)},
			scalar(0),
		)
		require.Error(t, err)
	})
}
