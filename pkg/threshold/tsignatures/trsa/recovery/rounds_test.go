package recovery_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa/recovery"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa/trusted_dealer"
)

const (
	threshold = 2
	total     = 3
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	identities, err := testutils.MakeDeterministicTestIdentities(total)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, threshold)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	shardValues := make([]*trsa.Shard, len(identities))
	for i, id := range identities {
		var ok bool
		shardValues[i], ok = shards.Get(id)
		require.True(t, ok)
	}

	// pretend Alice lost her shard
	alice, err := recovery.NewMislayer(identities[0].(types.AuthKey), protocol)
	require.NoError(t, err)

	bob, err := recovery.NewRecoverer(identities[1].(types.AuthKey), protocol, shardValues[1], alice.IdentityKey())
	require.NoError(t, err)
	charlie, err := recovery.NewRecoverer(identities[2].(types.AuthKey), protocol, shardValues[2], alice.IdentityKey())
	require.NoError(t, err)

	r1o := make([]network.RoundMessages[types.ThresholdProtocol, *recovery.Round1P2P], len(identities))
	r1o[1], err = bob.Round1()
	require.NoError(t, err)
	r1o[2], err = charlie.Round1()
	require.NoError(t, err)

	r2i := testutils.MapUnicastO2I(t, []types.Participant{alice, bob, charlie}, r1o)
	recoveredShard, err := alice.Round2(r2i[0])
	require.NoError(t, err)
	require.True(t, recoveredShard.Equal(shardValues[0]))
	require.NotNil(t, recoveredShard)
}
