package feldman_vss_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

var supportedAccessStructures = []struct{ th, n uint }{
	{2, 2},
	{2, 3},
	{3, 3},
	{3, 5},
	{7, 18},
}

func TestFeldmanHappyPath(t *testing.T) {
	t.Parallel()

	for _, as := range supportedAccessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			t.Run("k256", func(t *testing.T) {
				t.Parallel()
				curve := k256.NewCurve()
				testFeldmanHappyPath(t, as.th, as.n, curve)
			})
			t.Run("p256", func(t *testing.T) {
				t.Parallel()
				curve := p256.NewCurve()
				testFeldmanHappyPath(t, as.th, as.n, curve)
			})
			t.Run("edwards25519", func(t *testing.T) {
				t.Parallel()
				curve := edwards25519.NewCurve()
				testFeldmanHappyPath(t, as.th, as.n, curve)
			})
			t.Run("pallas", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewPallasCurve()
				testFeldmanHappyPath(t, as.th, as.n, curve)
			})
			t.Run("vesta", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewVestaCurve()
				testFeldmanHappyPath(t, as.th, as.n, curve)
			})
			t.Run("bls12381g1", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG1Curve()
				testFeldmanHappyPath(t, as.th, as.n, curve)
			})
			t.Run("vesta", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG2Curve()
				testFeldmanHappyPath(t, as.th, as.n, curve)
			})
		})
	}
}

func TestFeldmanLinearAdd(t *testing.T) {
	t.Parallel()

	for _, as := range supportedAccessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			t.Run("k256", func(t *testing.T) {
				t.Parallel()
				curve := k256.NewCurve()
				testFeldmanLinearAdd(t, as.th, as.n, curve)
			})
			t.Run("p256", func(t *testing.T) {
				t.Parallel()
				curve := p256.NewCurve()
				testFeldmanLinearAdd(t, as.th, as.n, curve)
			})
			t.Run("edwards25519", func(t *testing.T) {
				t.Parallel()
				curve := edwards25519.NewCurve()
				testFeldmanLinearAdd(t, as.th, as.n, curve)
			})
			t.Run("pallas", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewPallasCurve()
				testFeldmanLinearAdd(t, as.th, as.n, curve)
			})
			t.Run("vesta", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewVestaCurve()
				testFeldmanLinearAdd(t, as.th, as.n, curve)
			})
			t.Run("bls12381g1", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG1Curve()
				testFeldmanLinearAdd(t, as.th, as.n, curve)
			})
			t.Run("vesta", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG2Curve()
				testFeldmanLinearAdd(t, as.th, as.n, curve)
			})
		})
	}
}

func testFeldmanHappyPath[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tb testing.TB, th, n uint, curve C) {
	tb.Helper()

	prng := crand.Reader
	scheme, err := feldman_vss.NewScheme(th, n, curve)
	require.NoError(tb, err)
	require.NotNil(tb, scheme)

	randomScalar, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)

	shares, commitmentVector, err := scheme.DealVerifiable(randomScalar, prng)
	require.NoError(tb, err)
	require.NotNil(tb, shares)
	require.Len(tb, commitmentVector, int(th))
	for _, share := range shares {
		err = scheme.VerifyShare(share, commitmentVector)
		require.NoError(tb, err)
	}

	secret, err := scheme.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(tb, err)
	require.True(tb, secret.Equal(randomScalar))
}

// TODO(mkk): test other linear ops
func testFeldmanLinearAdd[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tb testing.TB, th, n uint, curve C) {
	tb.Helper()
	prng := crand.Reader

	scheme, err := feldman_vss.NewScheme(th, n, curve)
	require.NoError(tb, err)
	require.NotNil(tb, scheme)

	randomScalarA, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)
	randomScalarB, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)

	randomScalar := randomScalarA.Add(randomScalarB)

	sharesA, commitmentVectorA, err := scheme.DealVerifiable(randomScalarA, prng)
	require.NoError(tb, err)
	require.NotNil(tb, sharesA)
	require.Len(tb, commitmentVectorA, int(th))
	sharesB, commitmentVectorB, err := scheme.DealVerifiable(randomScalarB, prng)
	require.NoError(tb, err)
	require.NotNil(tb, sharesB)
	require.Len(tb, commitmentVectorB, int(th))

	shares := maputils.Join(sharesA, sharesB, func(_ types.SharingID, l, r *feldman_vss.Share[S]) *feldman_vss.Share[S] {
		return scheme.ShareAdd(l, r)
	})
	commitmentVector := scheme.VerificationAdd(commitmentVectorA, commitmentVectorB)

	for _, share := range shares {
		err = scheme.VerifyShare(share, commitmentVector)
		require.NoError(tb, err)
	}

	secret, err := scheme.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(tb, err)
	require.True(tb, secret.Equal(randomScalar))
}
