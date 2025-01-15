package lindell17_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
)

func Test_ShardSerialisationToJsonRoundTrip(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	hash := sha256.New
	cipherSuite, err := testutils.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)

	require.NotNil(t, shards)
	require.Equal(t, shards.Size(), int(protocol.TotalParties()))

	for _, holder := range identities {
		shard, exists := shards.Get(holder)
		require.True(t, exists)
		require.NoError(t, shard.Validate(protocol, holder, true))

		jsonBytes, err := json.Marshal(shard)
		require.NoError(t, err)
		require.NotNil(t, jsonBytes)

		var unmarshalledShard *lindell17.Shard
		err = json.Unmarshal(jsonBytes, &unmarshalledShard)
		require.NoError(t, err)
		require.NotNil(t, unmarshalledShard)

		err = unmarshalledShard.Validate(protocol, holder, true)
		require.NoError(t, err)
		require.True(t, shard.Equal(unmarshalledShard))

	}
}
