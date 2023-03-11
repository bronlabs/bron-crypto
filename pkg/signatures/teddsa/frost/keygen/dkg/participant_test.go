package dkg

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
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

	cohortConfig := &integration.CohortConfig{
		Curve:                curve,
		Protocol:             protocol.FROST,
		Hash:                 sha512.New512_256,
		Threshold:            2,
		TotalParties:         2,
		Participants:         identityKeys,
		SignatureAggregators: identityKeys,
	}
	alice, err := NewDKGParticipant(aliceIdentityKey, cohortConfig, crand.Reader)
	bob, err := NewDKGParticipant(bobIdentityKey, cohortConfig, crand.Reader)
	for _, party := range []*DKGParticipant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Len(t, party.shamirIdToIdentityKey, 2)
		require.Nil(t, party.secretKeyShare)
		require.Nil(t, party.myPartialPublicKey)
		require.Nil(t, party.publicKey)
	}
	require.NotEqual(t, alice.MyShamirId, bob.MyShamirId)
}
