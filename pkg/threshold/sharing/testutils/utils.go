package sharing_tu

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/stretchr/testify/require"
)

func MakeThresholdAccessStructure(tb testing.TB, threshold int, quorum network.Quorum) *shamir.AccessStructure {
	if threshold < 2 {
		tb.FailNow()
	}
	as, err := shamir.NewAccessStructure(uint(threshold), quorum)
	require.NoError(tb, err)
	return as
}
