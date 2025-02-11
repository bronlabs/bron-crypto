package feldman_vss_test

import (
	crand "crypto/rand"
	"maps"
	"slices"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/base/utils/maputils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
)

var supportedCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pasta.NewPallasCurve(),
	pasta.NewVestaCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

var supportedAccessStructures = []struct{ th, n uint }{
	{2, 2},
	{2, 3},
	{3, 3},
	{3, 5},
	{7, 18},
}

func TestFeldmanHappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		for _, as := range supportedAccessStructures {
			t.Run(spew.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
				t.Parallel()

				scheme, err := feldman_vss.NewScheme(as.th, as.n, curve)
				require.NoError(t, err)
				require.NotNil(t, scheme)

				randomScalar, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				shares, commitmentVector, err := scheme.DealVerifiable(randomScalar, prng)
				require.NoError(t, err)
				require.NotNil(t, shares)
				require.Len(t, commitmentVector, int(as.th))
				for _, share := range shares {
					err = scheme.VerifyShare(share, commitmentVector)
					require.NoError(t, err)
				}

				secret, err := scheme.Open(slices.Collect(maps.Values(shares))...)
				require.NoError(t, err)
				require.True(t, secret.Equal(randomScalar))
			})
		}
	}
}

// TODO(mkk): test other linear ops
func TestFeldmanLinearAdd(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		for _, as := range supportedAccessStructures {
			t.Run(spew.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
				t.Parallel()

				scheme, err := feldman_vss.NewScheme(as.th, as.n, curve)
				require.NoError(t, err)
				require.NotNil(t, scheme)

				randomScalarA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				randomScalarB, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				randomScalar := randomScalarA.Add(randomScalarB)

				sharesA, commitmentVectorA, err := scheme.DealVerifiable(randomScalarA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, commitmentVectorA, int(as.th))
				sharesB, commitmentVectorB, err := scheme.DealVerifiable(randomScalarB, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesB)
				require.Len(t, commitmentVectorB, int(as.th))

				shares := maputils.Join(sharesA, sharesB, func(_ types.SharingID, l, r *feldman_vss.Share) *feldman_vss.Share {
					return scheme.ShareAdd(l, r)
				})
				commitmentVector := scheme.VerificationAdd(commitmentVectorA, commitmentVectorB)

				for _, share := range shares {
					err = scheme.VerifyShare(share, commitmentVector)
					require.NoError(t, err)
				}

				secret, err := scheme.Open(slices.Collect(maps.Values(shares))...)
				require.NoError(t, err)
				require.True(t, secret.Equal(randomScalar))
			})
		}
	}
}
