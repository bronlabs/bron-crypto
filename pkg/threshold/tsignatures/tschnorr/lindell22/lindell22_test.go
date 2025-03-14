package lindell22_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
)

func Test_ShardSerialisationToJSONRoundTrip(t *testing.T) {
	t.Parallel()

	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	prng := crand.Reader
	th := 2
	n := 3

	cipherSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)

	shard, exists := shards.Get(identities[0])
	require.True(t, exists)

	err = shard.Validate(protocol)
	require.NoError(t, err)

	jsonBytes, err := json.Marshal(shard)
	require.NoError(t, err)
	require.NotNil(t, jsonBytes)

	var unmarshalledShard *lindell22.Shard
	err = json.Unmarshal(jsonBytes, &unmarshalledShard)
	require.NoError(t, err)
	require.NotNil(t, unmarshalledShard)

	err = unmarshalledShard.Validate(protocol)
	require.NoError(t, err)
	require.True(t, unmarshalledShard.Equal(shard))
}
