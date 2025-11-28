package algebrautils_test

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

func TestRandomNonIdentity(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	// Test with nil monoid
	_, err := algebrautils.RandomNonIdentity[*k256.Curve, *k256.Point](nil, bytes.NewReader(make([]byte, 100)))
	require.Error(t, err)

	// Test with nil prng
	_, err = algebrautils.RandomNonIdentity(curve, nil)
	require.Error(t, err)

	// Test successful random sampling
	prng := bytes.NewReader(make([]byte, 1000))
	result, err := algebrautils.RandomNonIdentity(curve, prng)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsOpIdentity())
}

func TestFold(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	// Create some points
	g := curve.Generator()
	p1 := g
	p2 := g.Op(g)
	p3 := g.Op(g).Op(g)

	// Test with single element
	result := algebrautils.Fold(p1)
	require.True(t, result.Equal(p1))

	// Test with multiple elements
	result = algebrautils.Fold(p1, p2, p3)
	expected := p1.Op(p2).Op(p3)
	require.True(t, result.Equal(expected))
}

func TestSum(t *testing.T) {
	t.Parallel()
	scalarField := k256.NewScalarField()

	// Create some scalars
	s1, err := scalarField.FromCardinal(cardinal.New(5))
	require.NoError(t, err)
	s2, err := scalarField.FromCardinal(cardinal.New(10))
	require.NoError(t, err)
	s3, err := scalarField.FromCardinal(cardinal.New(15))
	require.NoError(t, err)

	// Test with single element
	result := algebrautils.Sum(s1)
	require.True(t, result.Equal(s1))

	// Test with multiple elements
	result = algebrautils.Sum(s1, s2, s3)
	expected := s1.Add(s2).Add(s3)
	require.True(t, result.Equal(expected))
}

func TestProd(t *testing.T) {
	t.Parallel()
	scalarField := k256.NewScalarField()

	// Create some scalars
	s1, err := scalarField.FromCardinal(cardinal.New(5))
	require.NoError(t, err)
	s2, err := scalarField.FromCardinal(cardinal.New(10))
	require.NoError(t, err)
	s3, err := scalarField.FromCardinal(cardinal.New(15))
	require.NoError(t, err)

	// Test with single element
	result := algebrautils.Prod(s1)
	require.True(t, result.Equal(s1))

	// Test with multiple elements
	result = algebrautils.Prod(s1, s2, s3)
	expected := s1.Mul(s2).Mul(s3)
	require.True(t, result.Equal(expected))
}

func TestScalarMul(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	// Get generator point
	g := curve.Generator()

	// Test with scalar 0 (should return identity)
	scalar0 := num.N().FromUint64(0)
	result := algebrautils.ScalarMul(g, scalar0)
	require.True(t, result.IsOpIdentity())

	// Test with scalar 1 (should return base)
	scalar1 := num.N().FromUint64(1)
	result = algebrautils.ScalarMul(g, scalar1)
	require.True(t, result.Equal(g))

	// Test with scalar 2
	scalar2 := num.N().FromUint64(2)
	result = algebrautils.ScalarMul(g, scalar2)
	expected := g.Op(g)
	require.True(t, result.Equal(expected))

	// Test with larger scalar
	scalar5 := num.N().FromUint64(5)
	result = algebrautils.ScalarMul(g, scalar5)
	expected = g.Op(g).Op(g).Op(g).Op(g)
	require.True(t, result.Equal(expected))
}

func TestPippengerMultiScalarMul_K256(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	scalarField := k256.NewScalarField()
	g := curve.Generator()

	t.Run("single point matches ScalarMul", func(t *testing.T) {
		scalar := scalarField.FromUint64(42)
		points := []*k256.Point{g}
		scalars := []*k256.Scalar{scalar}

		result := algebrautils.MultiScalarMul(scalars, points)
		expected := algebrautils.ScalarMul(g, scalar)
		require.True(t, result.Equal(expected))
	})

	t.Run("all zero scalars returns identity", func(t *testing.T) {
		p1, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p2, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		zero := scalarField.Zero()
		points := []*k256.Point{p1, p2}
		scalars := []*k256.Scalar{zero, zero}

		result := algebrautils.MultiScalarMul(scalars, points)
		require.True(t, result.IsOpIdentity())
	})

	t.Run("all one scalars returns sum of points", func(t *testing.T) {
		p1, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p2, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p3, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		one := scalarField.One()
		points := []*k256.Point{p1, p2, p3}
		scalars := []*k256.Scalar{one, one, one}

		result := algebrautils.MultiScalarMul(scalars, points)
		expected := p1.Op(p2).Op(p3)
		require.True(t, result.Equal(expected))
	})

	t.Run("small known values", func(t *testing.T) {
		// Test: 2*G + 3*G = 5*G
		two := scalarField.FromUint64(2)
		three := scalarField.FromUint64(3)
		five := scalarField.FromUint64(5)

		points := []*k256.Point{g, g}
		scalars := []*k256.Scalar{two, three}

		result := algebrautils.MultiScalarMul(scalars, points)
		expected := algebrautils.ScalarMul(g, five)
		require.True(t, result.Equal(expected))
	})

	t.Run("mixed zero and non-zero scalars", func(t *testing.T) {
		p1, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p2, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p3, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		zero := scalarField.Zero()
		two := scalarField.FromUint64(2)
		points := []*k256.Point{p1, p2, p3}
		scalars := []*k256.Scalar{two, zero, two}

		result := algebrautils.MultiScalarMul(scalars, points)
		// Expected: 2*p1 + 0*p2 + 2*p3 = 2*p1 + 2*p3
		expected := algebrautils.ScalarMul(p1, two).Op(algebrautils.ScalarMul(p3, two))
		require.True(t, result.Equal(expected))
	})

	t.Run("identity point in input", func(t *testing.T) {
		identity := curve.OpIdentity()
		p1, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		two := scalarField.FromUint64(2)
		three := scalarField.FromUint64(3)
		points := []*k256.Point{identity, p1}
		scalars := []*k256.Scalar{three, two}

		result := algebrautils.MultiScalarMul(scalars, points)
		// Expected: 3*identity + 2*p1 = 2*p1
		expected := algebrautils.ScalarMul(p1, two)
		require.True(t, result.Equal(expected))
	})

	t.Run("random batch correctness", func(t *testing.T) {
		const n = 20
		points := make([]*k256.Point, n)
		scalars := make([]*k256.Scalar, n)

		for i := range n {
			p, err := curve.Random(crand.Reader)
			require.NoError(t, err)
			points[i] = p

			s, err := scalarField.Random(crand.Reader)
			require.NoError(t, err)
			scalars[i] = s
		}

		result := algebrautils.MultiScalarMul(scalars, points)

		// Compute expected using naive method
		expected := curve.OpIdentity()
		for i := range n {
			expected = expected.Op(algebrautils.ScalarMul(points[i], scalars[i]))
		}

		require.True(t, result.Equal(expected))
	})

	t.Run("consistency - same inputs same output", func(t *testing.T) {
		p1, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p2, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		s1 := scalarField.FromUint64(12345)
		s2 := scalarField.FromUint64(67890)

		points := []*k256.Point{p1, p2}
		scalars := []*k256.Scalar{s1, s2}

		result1 := algebrautils.MultiScalarMul(scalars, points)
		result2 := algebrautils.MultiScalarMul(scalars, points)

		require.True(t, result1.Equal(result2))
	})

	t.Run("empty input panics", func(t *testing.T) {
		require.Panics(t, func() {
			algebrautils.MultiScalarMul([]*k256.Scalar{}, []*k256.Point{})
		})
	})

	t.Run("mismatched lengths panics", func(t *testing.T) {
		require.Panics(t, func() {
			algebrautils.MultiScalarMul(
				[]*k256.Scalar{scalarField.One()},
				[]*k256.Point{g, g},
			)
		})
	})
}

func TestPippengerMultiScalarMul_Edwards25519(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewPrimeSubGroup()
	scalarField := edwards25519.NewScalarField()
	g := curve.Generator()

	t.Run("single point matches ScalarMul", func(t *testing.T) {
		scalar := scalarField.FromUint64(42)
		points := []*edwards25519.PrimeSubGroupPoint{g}
		scalars := []*edwards25519.Scalar{scalar}

		result := algebrautils.MultiScalarMul(scalars, points)
		expected := algebrautils.ScalarMul(g, scalar)
		require.True(t, result.Equal(expected))
	})

	t.Run("all zero scalars returns identity", func(t *testing.T) {
		p1, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p2, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		zero := scalarField.Zero()
		points := []*edwards25519.PrimeSubGroupPoint{p1, p2}
		scalars := []*edwards25519.Scalar{zero, zero}

		result := algebrautils.MultiScalarMul(scalars, points)
		require.True(t, result.IsOpIdentity())
	})

	t.Run("all one scalars returns sum of points", func(t *testing.T) {
		p1, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p2, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p3, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		one := scalarField.One()
		points := []*edwards25519.PrimeSubGroupPoint{p1, p2, p3}
		scalars := []*edwards25519.Scalar{one, one, one}

		result := algebrautils.MultiScalarMul(scalars, points)
		expected := p1.Op(p2).Op(p3)
		require.True(t, result.Equal(expected))
	})

	t.Run("small known values", func(t *testing.T) {
		// Test: 2*G + 3*G = 5*G
		two := scalarField.FromUint64(2)
		three := scalarField.FromUint64(3)
		five := scalarField.FromUint64(5)

		points := []*edwards25519.PrimeSubGroupPoint{g, g}
		scalars := []*edwards25519.Scalar{two, three}

		result := algebrautils.MultiScalarMul(scalars, points)
		expected := algebrautils.ScalarMul(g, five)
		require.True(t, result.Equal(expected))
	})

	t.Run("mixed zero and non-zero scalars", func(t *testing.T) {
		p1, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p2, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p3, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		zero := scalarField.Zero()
		two := scalarField.FromUint64(2)
		points := []*edwards25519.PrimeSubGroupPoint{p1, p2, p3}
		scalars := []*edwards25519.Scalar{two, zero, two}

		result := algebrautils.MultiScalarMul(scalars, points)
		// Expected: 2*p1 + 0*p2 + 2*p3 = 2*p1 + 2*p3
		expected := algebrautils.ScalarMul(p1, two).Op(algebrautils.ScalarMul(p3, two))
		require.True(t, result.Equal(expected))
	})

	t.Run("identity point in input", func(t *testing.T) {
		identity := curve.OpIdentity()
		p1, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		two := scalarField.FromUint64(2)
		three := scalarField.FromUint64(3)
		points := []*edwards25519.PrimeSubGroupPoint{identity, p1}
		scalars := []*edwards25519.Scalar{three, two}

		result := algebrautils.MultiScalarMul(scalars, points)
		// Expected: 3*identity + 2*p1 = 2*p1
		expected := algebrautils.ScalarMul(p1, two)
		require.True(t, result.Equal(expected))
	})

	t.Run("random batch correctness", func(t *testing.T) {
		const n = 20
		points := make([]*edwards25519.PrimeSubGroupPoint, n)
		scalars := make([]*edwards25519.Scalar, n)

		for i := range n {
			p, err := curve.Random(crand.Reader)
			require.NoError(t, err)
			points[i] = p

			s, err := scalarField.Random(crand.Reader)
			require.NoError(t, err)
			scalars[i] = s
		}

		result := algebrautils.MultiScalarMul(scalars, points)

		// Compute expected using naive method
		expected := curve.OpIdentity()
		for i := range n {
			expected = expected.Op(algebrautils.ScalarMul(points[i], scalars[i]))
		}

		require.True(t, result.Equal(expected))
	})

	t.Run("consistency - same inputs same output", func(t *testing.T) {
		p1, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		p2, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		s1 := scalarField.FromUint64(12345)
		s2 := scalarField.FromUint64(67890)

		points := []*edwards25519.PrimeSubGroupPoint{p1, p2}
		scalars := []*edwards25519.Scalar{s1, s2}

		result1 := algebrautils.MultiScalarMul(scalars, points)
		result2 := algebrautils.MultiScalarMul(scalars, points)

		require.True(t, result1.Equal(result2))
	})

	t.Run("empty input panics", func(t *testing.T) {
		require.Panics(t, func() {
			algebrautils.MultiScalarMul([]*edwards25519.Scalar{}, []*edwards25519.PrimeSubGroupPoint{})
		})
	})

	t.Run("mismatched lengths panics", func(t *testing.T) {
		require.Panics(t, func() {
			algebrautils.MultiScalarMul(
				[]*edwards25519.Scalar{scalarField.One()},
				[]*edwards25519.PrimeSubGroupPoint{g, g},
			)
		})
	})
}
