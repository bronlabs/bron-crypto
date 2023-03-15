package interactive_signing

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	trusted_dealer "github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/keygen/ed25519_trusted_dealer"
	"github.com/stretchr/testify/require"
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

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := curves.ED25519()
	alicePublicKey := curve.Point.Random(crand.Reader)
	aliceIdentityKey := &mockedIdentityKey{
		curve:     curve,
		publicKey: alicePublicKey,
	}

	bobPublicKey := curve.Point.Random(crand.Reader)
	bobIdentityKey := &mockedIdentityKey{
		curve:     curve,
		publicKey: bobPublicKey,
	}

	identityKeys := []integration.IdentityKey{aliceIdentityKey, bobIdentityKey}

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha512.New512_256,
	}

	cohortConfig := &integration.CohortConfig{
		CipherSuite:          cipherSuite,
		Protocol:             protocol.FROST,
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

	alice, err := NewInteractiveCosigner(aliceIdentityKey, aliceSigningKeyShare, nil, cohortConfig, crand.Reader)
	bob, err := NewInteractiveCosigner(bobIdentityKey, bobSigningKeyShare, nil, cohortConfig, crand.Reader)
	for _, party := range []*InteractiveCosigner{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Len(t, party.shamirIdToIdentityKey, 2)
		require.NotNil(t, party.SigningKeyShare)
	}
	require.NotEqual(t, alice.MyShamirId, bob.MyShamirId)
}
