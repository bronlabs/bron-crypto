package lp_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/lp"
)

func TestSmoke(t *testing.T) {
	t.Parallel()
	// As per "Recommendation for Key Management (2019-2030)" SP 800-57
	//  Part 1 Rev. 5, NIST, 05/2020 (https://www.keylength.com/en/4/)
	require.GreaterOrEqual(t, lp.PaillierBitSize, 2048,
		"PaillierBitSize should map into at least 112 bits of security")
}
