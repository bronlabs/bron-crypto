package signing_helpers

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton/pkg/base/protocols"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tschnorr/frost"
	trusted_dealer "github.com/copperexchange/krypton/pkg/threshold/tsignatures/tschnorr/frost/keygen/ed25519_trusted_dealer"
)

type mockedIdentityKey struct {
	curve     curves.Curve
	publicKey curves.Point

	_ types.Incomparable
}

func (k *mockedIdentityKey) PublicKey() curves.Point {
	return k.publicKey
}

func (k *mockedIdentityKey) Hash() [32]byte {
	return sha3.Sum256(k.publicKey.ToAffineCompressed())
}

func (k *mockedIdentityKey) Sign(message []byte) []byte {
	return []byte("mocked")
}

func (k *mockedIdentityKey) Verify(signature []byte, publicKey curves.Point, message []byte) error {
	return errors.New("not implemented")
}

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.New()
	alicePublicKey := curve.Point().Random(crand.Reader)
	aliceIdentityKey := &mockedIdentityKey{
		curve:     curve,
		publicKey: alicePublicKey,
	}

	bobPublicKey := curve.Point().Random(crand.Reader)
	bobIdentityKey := &mockedIdentityKey{
		curve:     curve,
		publicKey: bobPublicKey,
	}

	identityKeys := []integration.IdentityKey{aliceIdentityKey, bobIdentityKey}
	aliceSessionParticipants := []integration.IdentityKey{aliceIdentityKey, bobIdentityKey}
	bobSessionParticipants := []integration.IdentityKey{aliceIdentityKey, bobIdentityKey}

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha512.New512_256,
	}

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identityKeys),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.FROST,
			Threshold:            2,
			TotalParties:         2,
			SignatureAggregators: hashset.NewHashSet(identityKeys),
		},
	}
	identityKeysToSigningKeyShares, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(t, err)

	aliceSigningKeyShare, exists := identityKeysToSigningKeyShares[aliceIdentityKey.Hash()]
	require.True(t, exists)
	require.NotNil(t, aliceSigningKeyShare)

	bobSigningKeyShare, exists := identityKeysToSigningKeyShares[bobIdentityKey.Hash()]
	require.True(t, exists)
	require.NotNil(t, bobSigningKeyShare)

	aliceShard := frost.Shard{
		SigningKeyShare: aliceSigningKeyShare,
		PublicKeyShares: nil,
	}

	bobShard := frost.Shard{
		SigningKeyShare: bobSigningKeyShare,
		PublicKeyShares: nil,
	}

	alice, err := NewInteractiveCosigner(aliceIdentityKey, hashset.NewHashSet(aliceSessionParticipants), &aliceShard, cohortConfig, crand.Reader)
	require.NoError(t, err)
	bob, err := NewInteractiveCosigner(bobIdentityKey, hashset.NewHashSet(bobSessionParticipants), &bobShard, cohortConfig, crand.Reader)
	require.NoError(t, err)
	for _, party := range []*Cosigner{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Len(t, party.SharingIdToIdentityKey, 2)
		require.NotNil(t, party.Shard)
	}
	require.NotEqual(t, alice.MySharingId, bob.MySharingId)
}
