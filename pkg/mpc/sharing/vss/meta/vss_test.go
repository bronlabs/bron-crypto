package meta_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta"
)

func TestNewFeldmanSchemeWithShamir(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()

	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := accessstructures.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shamirScheme, err := shamir.NewScheme(field, ac)
	require.NoError(t, err)

	scheme, err := meta.NewFeldmanScheme[
		*shamir.Share[*k256.Scalar], *k256.Scalar,
		*shamir.Secret[*k256.Scalar], *k256.Scalar,
		*shamir.DealerOutput[*k256.Scalar],
		*accessstructures.Threshold,
		*shamir.DealerFunc[*k256.Scalar],
		*shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar],
	](curve.Generator(), shamirScheme)
	require.NoError(t, err)

	secret := shamir.NewSecret(field.FromUint64(42))
	dealerOutput, err := scheme.Deal(secret, prng)
	require.NoError(t, err)

	vm := dealerOutput.VerificationMaterial()
	for _, share := range dealerOutput.Shares().Values() {
		require.NoError(t, scheme.Verify(share, vm))
	}

	reconstructed, err := scheme.ReconstructAndVerify(vm, dealerOutput.Shares().Values()...)
	require.NoError(t, err)
	require.True(t, secret.Equal(reconstructed))
}

func TestNewFeldmanSchemeWithISN(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()

	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := accessstructures.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	isnScheme, err := isn.NewFiniteScheme[*k256.Scalar](field, ac)
	require.NoError(t, err)

	scheme, err := meta.NewFeldmanScheme[
		*isn.Share[*k256.Scalar], *k256.Scalar,
		*isn.Secret[*k256.Scalar], *k256.Scalar,
		*isn.DealerOutput[*k256.Scalar],
		*accessstructures.CNF,
		isn.DealerFunc[*k256.Scalar],
		isn.LiftedDealerFunc[*k256.Point, *k256.Scalar],
		*isn.LiftedShare[*k256.Point],
		*k256.Point,
	](curve.Generator(), isnScheme)
	require.NoError(t, err)

	secret := isn.NewSecret(field.FromUint64(42))
	dealerOutput, err := scheme.Deal(secret, prng)
	require.NoError(t, err)

	vm := dealerOutput.VerificationMaterial()
	for _, share := range dealerOutput.Shares().Values() {
		require.NoError(t, scheme.Verify(share, vm))
	}

	reconstructed, err := scheme.ReconstructAndVerify(vm, dealerOutput.Shares().Values()...)
	require.NoError(t, err)
	require.True(t, secret.Equal(reconstructed))
}

func TestNewPedersenSchemeWithShamir(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()

	g := curve.Generator()
	h, err := curve.Random(prng)
	require.NoError(t, err)
	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(t, err)

	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := accessstructures.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shamirScheme, err := shamir.NewScheme(field, ac)
	require.NoError(t, err)

	scheme, err := meta.NewPedersenScheme[
		*shamir.Share[*k256.Scalar], *k256.Scalar,
		*shamir.Secret[*k256.Scalar], *k256.Scalar,
		*shamir.DealerOutput[*k256.Scalar],
		*accessstructures.Threshold,
		*shamir.DealerFunc[*k256.Scalar],
		*shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar],
		*shamir.LiftedShare[*k256.Point, *k256.Scalar],
		*k256.Point,
	](key, shamirScheme)
	require.NoError(t, err)

	secret := shamir.NewSecret(field.FromUint64(42))
	dealerOutput, err := scheme.Deal(secret, prng)
	require.NoError(t, err)

	vv := dealerOutput.VerificationVector()
	for _, share := range dealerOutput.Shares().Values() {
		require.NoError(t, scheme.Verify(share, vv))
	}

	reconstructed, err := scheme.ReconstructAndVerify(vv, dealerOutput.Shares().Values()...)
	require.NoError(t, err)
	require.True(t, secret.Equal(reconstructed))
}

func TestNewPedersenSchemeWithISN(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()

	g := curve.Generator()
	h, err := curve.Random(prng)
	require.NoError(t, err)
	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(t, err)

	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := accessstructures.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	isnScheme, err := isn.NewFiniteScheme[*k256.Scalar](field, ac)
	require.NoError(t, err)

	scheme, err := meta.NewPedersenScheme[
		*isn.Share[*k256.Scalar], *k256.Scalar,
		*isn.Secret[*k256.Scalar], *k256.Scalar,
		*isn.DealerOutput[*k256.Scalar],
		*accessstructures.CNF,
		isn.DealerFunc[*k256.Scalar],
		isn.LiftedDealerFunc[*k256.Point, *k256.Scalar],
		*isn.LiftedShare[*k256.Point],
		*k256.Point,
	](key, isnScheme)
	require.NoError(t, err)

	secret := isn.NewSecret(field.FromUint64(42))
	dealerOutput, err := scheme.Deal(secret, prng)
	require.NoError(t, err)

	vv := dealerOutput.VerificationVector()
	for _, share := range dealerOutput.Shares().Values() {
		require.NoError(t, scheme.Verify(share, vv))
	}

	reconstructed, err := scheme.ReconstructAndVerify(vv, dealerOutput.Shares().Values()...)
	require.NoError(t, err)
	require.True(t, secret.Equal(reconstructed))
}
