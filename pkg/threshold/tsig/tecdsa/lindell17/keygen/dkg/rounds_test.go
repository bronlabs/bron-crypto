package dkg_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17/keygen/dkg/testutils"
)

func Test_Lindell17DKG_K256_2of3(t *testing.T) {
	t.Parallel()

	const THRESHOLD = 2
	const TOTAL = 3

	curve := k256.NewCurve()
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := sharing.ID(0); i < TOTAL; i++ {
		shareholders.Add(i)
	}
	accessStructure, err := shamir.NewAccessStructure(THRESHOLD, shareholders.Freeze())
	require.NoError(t, err)

	// Run DKG - all verification is done inside testutils
	shards := testutils.RunLindell17DKG(t, curve, accessStructure)
	require.Len(t, shards, TOTAL)

	// Verify each shard has proper auxiliary info
	for id, shard := range shards {
		require.NotNil(t, shard.PaillierPrivateKey(), "Shard %d should have Paillier private key", id)
		require.NotNil(t, shard.PaillierPublicKeys(), "Shard %d should have Paillier public keys", id)
		require.NotNil(t, shard.EncryptedShares(), "Shard %d should have encrypted shares", id)

		// Each shard should have public keys from all other parties
		require.Equal(t, TOTAL-1, shard.PaillierPublicKeys().Size(),
			"Shard %d should have %d Paillier public keys (one from each other party)", id, TOTAL-1)

		// Each shard should have encrypted shares from all other parties
		require.Equal(t, TOTAL-1, shard.EncryptedShares().Size(),
			"Shard %d should have %d encrypted shares (one from each other party)", id, TOTAL-1)
	}
}

func Test_Lindell17DKG_P256_2of3(t *testing.T) {
	t.Parallel()

	const THRESHOLD = 2
	const TOTAL = 3

	curve := p256.NewCurve()
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := sharing.ID(0); i < TOTAL; i++ {
		shareholders.Add(i)
	}
	accessStructure, err := shamir.NewAccessStructure(THRESHOLD, shareholders.Freeze())
	require.NoError(t, err)

	// Run DKG - all verification is done inside testutils
	shards := testutils.RunLindell17DKG(t, curve, accessStructure)
	require.Len(t, shards, TOTAL)

	// Verify each shard has proper auxiliary info
	for id, shard := range shards {
		require.NotNil(t, shard.PaillierPrivateKey(), "Shard %d should have Paillier private key", id)
		require.NotNil(t, shard.PaillierPublicKeys(), "Shard %d should have Paillier public keys", id)
		require.NotNil(t, shard.EncryptedShares(), "Shard %d should have encrypted shares", id)
	}
}

func Test_Lindell17DKG_K256_2of2(t *testing.T) {
	t.Parallel()

	const THRESHOLD = 2
	const TOTAL = 2

	curve := p256.NewCurve()
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := sharing.ID(1); i <= TOTAL; i++ {
		shareholders.Add(i)
	}
	accessStructure, err := shamir.NewAccessStructure(THRESHOLD, shareholders.Freeze())
	require.NoError(t, err)

	// Run DKG
	shards := testutils.RunLindell17DKG(t, curve, accessStructure)
	require.Len(t, shards, TOTAL)
}
