package signing_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/testutils"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()

	for _, config := range []struct {
		threshold int
		total     int
	}{
		{2, 2},
		{2, 3},
		{3, 3},
	} {
		boundedConfig := config
		t.Run(fmt.Sprintf("running happy path for t=%d and n=%d", boundedConfig.threshold, boundedConfig.total), func(t *testing.T) {
			t.Parallel()
			err := testutils.DoSignRoundTrip(t, boundedConfig.threshold, boundedConfig.total)
			require.NoError(t, err)
		})
		t.Run(fmt.Sprintf("running happy path for t=%d and n=%d", boundedConfig.threshold, boundedConfig.total), func(t *testing.T) {
			t.Parallel()
			err := testutils.DoSignWithDkg(t, boundedConfig.threshold, boundedConfig.total)
			require.NoError(t, err)
		})
	}
}
