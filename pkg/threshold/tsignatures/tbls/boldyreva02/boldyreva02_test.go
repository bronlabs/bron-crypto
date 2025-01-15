package boldyreva02_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/bls"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/trusted_dealer"
)

func shardJSONRoundTrip[K bls.KeySubGroup](t *testing.T) {
	t.Helper()
	hashFunc := sha512.New
	keySubGroup := bls12381.GetSourceSubGroup[K]()
	prng := crand.Reader
	th := 2
	n := 3

	cipherSuite, err := ttu.MakeSigningSuite(keySubGroup, hashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen[K](protocol, prng)
	require.NoError(t, err)

	shard, exists := shards.Get(identities[0])
	require.True(t, exists)

	jsonBytes, err := json.Marshal(shard)
	require.NoError(t, err)
	require.NotNil(t, jsonBytes)

	var unmarshalledShard *boldyreva02.Shard[K]
	err = json.Unmarshal(jsonBytes, &unmarshalledShard)
	require.NoError(t, err)
	require.NotNil(t, unmarshalledShard)

	err = unmarshalledShard.Validate(protocol)
	require.NoError(t, err)
	require.True(t, unmarshalledShard.Equal(shard))
}

func Test_ShardSerialisationToJSONRoundTrip(t *testing.T) {
	t.Parallel()
	t.Run("G1", func(t *testing.T) {
		t.Parallel()
		shardJSONRoundTrip[bls12381.G1](t)
	})
	t.Run("G2", func(t *testing.T) {
		t.Parallel()
		shardJSONRoundTrip[bls12381.G2](t)
	})
}
