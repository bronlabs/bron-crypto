package tripledh_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/tripledh"
)

func Test_HappyPathTripleDH(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		k256.New(),
		p256.New(),
		pallas.New(),
		edwards25519.New(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}

	for _, testCase := range supportedCurves {
		curve := testCase
		t.Run(fmt.Sprintf("x3dh for %s", curve.Name()), func(t *testing.T) {
			t.Parallel()

			aliceSk, err := curve.Scalar().Random(crand.Reader)
			require.NoError(t, err)
			alicePk := curve.ScalarBaseMult(aliceSk)
			aliceEsk, err := curve.Scalar().Random(crand.Reader)
			require.NoError(t, err)
			aliceEpk := curve.ScalarBaseMult(aliceEsk)
			bobSk, err := curve.Scalar().Random(crand.Reader)
			require.NoError(t, err)
			bobPk := curve.ScalarBaseMult(bobSk)
			bobEsk, err := curve.Scalar().Random(crand.Reader)
			require.NoError(t, err)
			bobEpk := curve.ScalarBaseMult(bobEsk)

			local, err := tripledh.DeriveSecretLocal(aliceSk, bobPk, aliceEsk, bobEpk)
			require.NoError(t, err)
			remote, err := tripledh.DeriveSecretRemote(alicePk, bobSk, aliceEpk, bobEsk)
			require.NoError(t, err)

			require.Zero(t, local.Cmp(remote))
		})
	}
}
