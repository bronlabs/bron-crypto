package newprzs_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/newprzs"
)

func Test_Dealer(t *testing.T) {
	n := 5
	threshold := 3
	field := k256.NewCurve().ScalarField()
	dealt, err := newprzs.Deal(n, threshold-1, field, crand.Reader)
	require.NoError(t, err)

	t.Run("every t parties have correct seeds", func(t *testing.T) {
		secrets := make([]curves.Scalar, 0)
		combinations := combin.Combinations(n, threshold)
		for _, combination := range combinations {
			seeds := make(map[int]curves.Scalar)
			for _, idx := range combination {
				for k, v := range dealt[idx] {
					seeds[k] = v
				}
			}
			secret := field.Zero()
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
