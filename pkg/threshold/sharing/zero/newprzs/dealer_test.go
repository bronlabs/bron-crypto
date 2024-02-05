package newprzs_test

import (
	crand "crypto/rand"
	"crypto/subtle"
	"testing"

	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/newprzs"
)

func Test_Dealer(t *testing.T) {
	n := 5
	threshold := 3
	dealt, err := newprzs.Deal(n, threshold-1, crand.Reader)
	require.NoError(t, err)

	t.Run("should every have correct seeds", func(t *testing.T) {
		secrets := make([]newprzs.Key, 0)
		combinations := combin.Combinations(n, threshold)
		for _, combination := range combinations {
			keys := make(map[int]newprzs.Key)
			for _, idx := range combination {
				for k, v := range dealt[idx] {
					keys[k] = v
				}
			}
			var secret newprzs.Key
			for _, key := range keys {
				oldSecret := secret
				var newSecret newprzs.Key
				subtle.XORBytes(newSecret[:], oldSecret[:], key[:])
				secret = newSecret
			}
			secrets = append(secrets, secret)
		}

		for i := 0; i < len(secrets)-1; i++ {
			require.Equal(t, secrets[i], secrets[i+1])
		}
	})
}
