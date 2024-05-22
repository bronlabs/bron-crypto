package commitments_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
)

func TestSmoke(t *testing.T) {
	require.GreaterOrEqual(t, commitments.CommitmentHashFunction().Size(), base.CollisionResistanceBytes,
		"hash function output length is too short")
}
