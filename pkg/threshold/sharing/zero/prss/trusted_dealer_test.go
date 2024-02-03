package prss_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/prss"
)

func Test_Dealer(t *testing.T) {
	threshold := 3
	n := 5
	curve := k256.NewCurve()
	h := sha256.New

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	config, err := testutils.MakeCohortProtocol(cipherSuite, protocols.DKLS24, identities, threshold, identities)
	require.NoError(t, err)

	dealt, err := prss.Deal(config, crand.Reader)
	require.NoError(t, err)

	t.Run("every t parties have correct seeds", func(t *testing.T) {
		secrets := make([]curves.Scalar, 0)
		combinations := combin.Combinations(n, threshold)
		for _, combination := range combinations {
			seeds := make(map[int]curves.Scalar)
			for _, idx := range combination {
				for k, v := range dealt[identities[idx].Hash()].Ra {
					seeds[k] = v
				}
			}
			secret := cipherSuite.Curve.ScalarField().Zero()
			for _, seed := range seeds {
				secret = secret.Add(seed)
			}
			secrets = append(secrets, secret)
		}

		for i := 0; i < len(secrets)-1; i++ {
			require.Equal(t, secrets[i], secrets[i+1])
		}
	})
}
