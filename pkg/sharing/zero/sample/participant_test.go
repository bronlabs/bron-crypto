package sample

import (
	crand "crypto/rand"
	"errors"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/hashing"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type mockedIdentityKey struct {
	curve     *curves.Curve
	publicKey curves.Point
}

func (k *mockedIdentityKey) PublicKey() curves.Point {
	return k.publicKey
}
func (k *mockedIdentityKey) Sign(message []byte) []byte {
	return []byte("mocked")
}
func (k *mockedIdentityKey) Verify(signature []byte, publicKey curves.Point, message []byte) error {
	return errors.New("not implemented")
}

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := curves.ED25519()
	cipherSuite := &integration.CipherSuite{Curve: curve, Hash: sha3.New256}
	identities, err := test_utils.MakeIdentities(cipherSuite, 2)
	require.NoError(t, err)
	aliceIdentityKey, bobIdentityKey := identities[0], identities[1]

	var sharedSeed zero.Seed
	hashed, err := hashing.Hash(sha3.New256, []byte("pepsi > coke"))
	require.NoError(t, err)
	copy(sharedSeed[:], hashed)

	aliceSeeds := zero.PairwiseSeeds{bobIdentityKey: sharedSeed}
	bobSeeds := zero.PairwiseSeeds{aliceIdentityKey: sharedSeed}

	alice, err := NewParticipant(curve, aliceIdentityKey, aliceSeeds, identities, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := NewParticipant(curve, bobIdentityKey, bobSeeds, identities, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, bob)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Len(t, party.IdentityKeyToSharingId, 2)
		require.Len(t, party.PresentParticipants, 2)
		require.NotNil(t, party.state)
	}
	require.NotEqual(t, alice.MySharingId, bob.MySharingId)
}
