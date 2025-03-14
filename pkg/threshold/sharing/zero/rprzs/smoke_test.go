package rprzs_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs"
)

func TestSmoke(t *testing.T) {
	t.Parallel()

	require.GreaterOrEqual(t, rprzs.LambdaBytes, base.CollisionResistanceBytes,
		"Ensure a minimum of 128-bit computational security")
}
