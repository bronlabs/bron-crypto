package algebrautils_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

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
