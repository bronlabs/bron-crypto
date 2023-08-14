package interactive

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost"
	trusted_dealer "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/keygen/ed25519_trusted_dealer"
)

type mockedIdentityKey struct {
	curve     curves.Curve
	publicKey curves.Point
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
		CipherSuite:          cipherSuite,
		Protocol:             protocols.FROST,
		Threshold:            2,
		TotalParties:         2,
		Participants:         identityKeys,
		SignatureAggregators: identityKeys,
	}
	identityKeysToSigningKeyShares, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(t, err)

	aliceSigningKeyShare, exists := identityKeysToSigningKeyShares[aliceIdentityKey]
	require.True(t, exists)
	require.NotNil(t, aliceSigningKeyShare)

	bobSigningKeyShare, exists := identityKeysToSigningKeyShares[bobIdentityKey]
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

	alice, err := NewInteractiveCosigner(aliceIdentityKey, aliceSessionParticipants, &aliceShard, cohortConfig, crand.Reader)
	require.NoError(t, err)
	bob, err := NewInteractiveCosigner(bobIdentityKey, bobSessionParticipants, &bobShard, cohortConfig, crand.Reader)
	require.NoError(t, err)
	for _, party := range []*Cosigner{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Len(t, party.SharingIdToIdentityKey, 2)
		require.NotNil(t, party.Shard)
	}
	require.NotEqual(t, alice.MySharingId, bob.MySharingId)
}
