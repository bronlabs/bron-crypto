package k256_test

import (
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

func Test_BaseFieldElementCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := k256.NewBaseField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(k256.BaseFieldElement)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_ScalarCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := k256.NewScalarField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(k256.Scalar)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_PointCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := k256.NewCurve().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(k256.Point)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

// naiveMultiScalarMul computes multi-scalar multiplication using the naive method
func naiveMultiScalarMul(scalars []*k256.Scalar, points []*k256.Point) *k256.Point {
	curve := k256.NewCurve()
	result := curve.OpIdentity()
	for i := range points {
		result = result.Op(points[i].ScalarMul(scalars[i]))
	}
	return result
}

func TestMultiScalarMul(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	scalarField := k256.NewScalarField()
	g := curve.Generator()

	t.Run("single point", func(t *testing.T) {
		t.Parallel()
		scalar := scalarField.FromUint64(42)
		points := []*k256.Point{g}
		scalars := []*k256.Scalar{scalar}

		result1, err := curve.MultiScalarMul(scalars, points)
		require.NoError(t, err)
		expected := g.ScalarMul(scalar)

		require.True(t, result1.Equal(expected), "MultiScalarMul failed for single point")
	})

	t.Run("all zero scalars returns identity", func(t *testing.T) {
		t.Parallel()
		p1, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)
		p2, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)

		zero := scalarField.Zero()
		points := []*k256.Point{p1, p2}
		scalars := []*k256.Scalar{zero, zero}

		result1, err := curve.MultiScalarMul(scalars, points)
		require.NoError(t, err)

		require.True(t, result1.IsOpIdentity(), "MultiScalarMul should return identity for all zero scalars")
	})

	t.Run("all one scalars returns sum of points", func(t *testing.T) {
		t.Parallel()
		p1, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)
		p2, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)
		p3, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)

		one := scalarField.One()
		points := []*k256.Point{p1, p2, p3}
		scalars := []*k256.Scalar{one, one, one}

		result1, err := curve.MultiScalarMul(scalars, points)
		require.NoError(t, err)
		expected := p1.Op(p2).Op(p3)

		require.True(t, result1.Equal(expected), "MultiScalarMul failed for all one scalars")
	})

	t.Run("small known values 2G + 3G = 5G", func(t *testing.T) {
		t.Parallel()
		two := scalarField.FromUint64(2)
		three := scalarField.FromUint64(3)
		five := scalarField.FromUint64(5)

		points := []*k256.Point{g, g}
		scalars := []*k256.Scalar{two, three}

		result1, err := curve.MultiScalarMul(scalars, points)
		require.NoError(t, err)
		expected := g.ScalarMul(five)

		require.True(t, result1.Equal(expected), "MultiScalarMul failed for 2G + 3G")
	})

	t.Run("mixed zero and non-zero scalars", func(t *testing.T) {
		t.Parallel()
		p1, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)
		p2, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)
		p3, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)

		zero := scalarField.Zero()
		two := scalarField.FromUint64(2)
		points := []*k256.Point{p1, p2, p3}
		scalars := []*k256.Scalar{two, zero, two}

		result1, err := curve.MultiScalarMul(scalars, points)
		require.NoError(t, err)
		expected := p1.ScalarMul(two).Op(p3.ScalarMul(two))

		require.True(t, result1.Equal(expected), "MultiScalarMul failed for mixed scalars")
	})

	t.Run("identity point in input", func(t *testing.T) {
		t.Parallel()
		identity := curve.OpIdentity()
		p1, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)

		two := scalarField.FromUint64(2)
		three := scalarField.FromUint64(3)
		points := []*k256.Point{identity, p1}
		scalars := []*k256.Scalar{three, two}

		result1, err := curve.MultiScalarMul(scalars, points)
		require.NoError(t, err)
		expected := p1.ScalarMul(two)

		require.True(t, result1.Equal(expected), "MultiScalarMul failed with identity point")
	})

	t.Run("random batch correctness", func(t *testing.T) {
		t.Parallel()
		const n = 20
		points := make([]*k256.Point, n)
		scalars := make([]*k256.Scalar, n)

		for i := range n {
			p, err := curve.Random(pcg.NewRandomised())
			require.NoError(t, err)
			points[i] = p

			s, err := scalarField.Random(pcg.NewRandomised())
			require.NoError(t, err)
			scalars[i] = s
		}

		result1, err := curve.MultiScalarMul(scalars, points)
		require.NoError(t, err)
		expected := naiveMultiScalarMul(scalars, points)

		require.True(t, result1.Equal(expected), "MultiScalarMul failed for random batch")
	})

	t.Run("consistency - same inputs same output", func(t *testing.T) {
		t.Parallel()
		p1, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)
		p2, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)

		s1 := scalarField.FromUint64(12345)
		s2 := scalarField.FromUint64(67890)

		points := []*k256.Point{p1, p2}
		scalars := []*k256.Scalar{s1, s2}

		result1a, err := curve.MultiScalarMul(scalars, points)
		require.NoError(t, err)
		result1b, err := curve.MultiScalarMul(scalars, points)
		require.NoError(t, err)

		require.True(t, result1a.Equal(result1b), "MultiScalarMul should be deterministic")
	})

}

func BenchmarkMultiScalarMul(b *testing.B) {
	curve := k256.NewCurve()
	scalarField := k256.NewScalarField()

	for _, n := range []int{2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 20} {
		points := make([]*k256.Point, n)
		scalars := make([]*k256.Scalar, n)

		for i := range n {
			p, _ := curve.Random(pcg.NewRandomised())
			points[i] = p
			s, _ := scalarField.Random(pcg.NewRandomised())
			scalars[i] = s
		}

		b.Run(fmt.Sprintf("MultiScalarMul/n=%d", n), func(b *testing.B) {
			for range b.N {
				_, _ = curve.MultiScalarMul(scalars, points)
			}
		})

		b.Run(fmt.Sprintf("algebrautils/n=%d", n), func(b *testing.B) {
			for range b.N {
				_ = algebrautils.MultiScalarMul(scalars, points)
			}
		})

		b.Run(fmt.Sprintf("Naive/n=%d", n), func(b *testing.B) {
			for range b.N {
				_ = naiveMultiScalarMul(scalars, points)
			}
		})
	}
}
