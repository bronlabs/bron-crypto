package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
	interactiveSigning "github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17/signing/interactive"
)

func Test_SignWithDerivedKeysBip32(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	hash := sha256.New
	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)
	alice, bob, charlie := identities[0], identities[1], identities[2]

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(t, err)

	message := []byte("Hello World!")

	parentShards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, parentShards)
	require.Equal(t, parentShards.Size(), int(protocol.TotalParties()))

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell17.ExtendedShard]()
	for id, parentShard := range parentShards.Iter() {
		shard, err := parentShard.Derive(77777)
		require.NoError(t, err)
		require.False(t, shard.PublicKey().Equal(parentShard.PublicKey()))
		shards.Put(id, shard)
	}

	aliceShard, exists := shards.Get(alice)
	require.True(t, exists)
	bobShard, exists := shards.Get(bob)
	require.True(t, exists)
	_, exists = shards.Get(charlie)
	require.True(t, exists)

	sessionId := []byte("TestSession")
	primary, err := interactiveSigning.NewPrimaryCosigner(sessionId, alice.(types.AuthKey), bob, aliceShard.AsShard(), protocol, cn, nil, crand.Reader)
	require.NotNil(t, primary)
	require.NoError(t, err)

	secondary, err := interactiveSigning.NewSecondaryCosigner(sessionId, bob.(types.AuthKey), alice, bobShard.AsShard(), protocol, cn, nil, crand.Reader)
	require.NotNil(t, secondary)
	require.NoError(t, err)

	r1, err := primary.Round1()
	require.NoError(t, err)

	r2, err := secondary.Round2(ttu.GobRoundTripMessage(t, r1))
	require.NoError(t, err)

	r3, err := primary.Round3(ttu.GobRoundTripMessage(t, r2))
	require.NoError(t, err)

	r4, err := secondary.Round4(ttu.GobRoundTripMessage(t, r3), message)
	require.NoError(t, err)

	signature, err := primary.Round5(ttu.GobRoundTripMessage(t, r4), message)
	require.NoError(t, err)

	err = ecdsa.Verify(signature, cipherSuite.Hash(), bobShard.PublicKey(), message)
	require.NoError(t, err)
}

func Test_SignWithDerivedKeysGeneric(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	hash := sha3.New256
	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)
	alice, bob, charlie := identities[0], identities[1], identities[2]

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(t, err)

	message := []byte("Hello World!")

	parentShards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, parentShards)
	require.Equal(t, parentShards.Size(), int(protocol.TotalParties()))

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell17.ExtendedShard]()
	for id, parentShard := range parentShards.Iter() {
		shard, err := parentShard.Derive(12345)
		require.NoError(t, err)
		require.False(t, shard.PublicKey().Equal(parentShard.PublicKey()))
		shards.Put(id, shard)
	}

	aliceShard, exists := shards.Get(alice)
	require.True(t, exists)
	bobShard, exists := shards.Get(bob)
	require.True(t, exists)
	_, exists = shards.Get(charlie)
	require.True(t, exists)

	sessionId := []byte("TestSession")
	primary, err := interactiveSigning.NewPrimaryCosigner(sessionId, alice.(types.AuthKey), bob, aliceShard.AsShard(), protocol, cn, nil, crand.Reader)
	require.NotNil(t, primary)
	require.NoError(t, err)

	secondary, err := interactiveSigning.NewSecondaryCosigner(sessionId, bob.(types.AuthKey), alice, bobShard.AsShard(), protocol, cn, nil, crand.Reader)
	require.NotNil(t, secondary)
	require.NoError(t, err)

	r1, err := primary.Round1()
	require.NoError(t, err)

	r2, err := secondary.Round2(ttu.GobRoundTripMessage(t, r1))
	require.NoError(t, err)

	r3, err := primary.Round3(ttu.GobRoundTripMessage(t, r2))
	require.NoError(t, err)

	r4, err := secondary.Round4(ttu.GobRoundTripMessage(t, r3), message)
	require.NoError(t, err)

	signature, err := primary.Round5(ttu.GobRoundTripMessage(t, r4), message)
	require.NoError(t, err)

	err = ecdsa.Verify(signature, cipherSuite.Hash(), bobShard.PublicKey(), message)
	require.NoError(t, err)
}
