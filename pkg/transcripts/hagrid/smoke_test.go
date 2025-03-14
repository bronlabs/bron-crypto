package hagrid_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestSmoke(t *testing.T) {
	t.Parallel()

	// Ensure a minimum of 128-bit computational security
	require.GreaterOrEqual(t, hagrid.StateSize, base.CollisionResistanceBytes,
		"Ensure a minimum of 128-bit computational security")
}
