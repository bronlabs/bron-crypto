package signing_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/testutils"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()

	for _, scheme := range []bls.RogueKeyPrevention{bls.Basic, bls.MessageAugmentation, bls.POP} {
		boundedScheme := scheme
		for _, config := range []struct {
			threshold int
			total     int
		}{
			{2, 2},
			{2, 3},
			{3, 3},
		} {
			boundedConfig := config
			t.Run(fmt.Sprintf("running happy path for scheme=%d t=%d and n=%d", boundedScheme, boundedConfig.threshold, boundedConfig.total), func(t *testing.T) {
				t.Parallel()
				t.Run("short keys", func(t *testing.T) {
					t.Parallel()
					err := testutils.SigningRoundTrip[bls.G1, bls.G2](boundedConfig.threshold, boundedConfig.total, boundedScheme)
					require.NoError(t, err)
				})
				t.Run("short signatures", func(t *testing.T) {
					t.Parallel()
					err := testutils.SigningRoundTrip[bls.G2, bls.G1](boundedConfig.threshold, boundedConfig.total, boundedScheme)
					require.NoError(t, err)
				})
			})
		}
	}
}
