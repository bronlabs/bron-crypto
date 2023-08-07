package gennaro

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
)

type mockedIdentityKey struct {
	curve     *curves.Curve
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
		Protocol:             protocols.FROST,
		Threshold:            2,
		TotalParties:         2,
		Participants:         identityKeys,
		SignatureAggregators: identityKeys,
	}
	alice, err := NewParticipant([]byte("sid"), aliceIdentityKey, cohortConfig, crand.Reader, nil)
	require.NoError(t, err)
	bob, err := NewParticipant([]byte("sid"), bobIdentityKey, cohortConfig, crand.Reader, nil)
	require.NoError(t, err)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Len(t, party.shamirIdToIdentityKey, 2)
	}
	require.NotEqual(t, alice.MyShamirId, bob.MyShamirId)
	require.True(t, alice.H.Equal(bob.H))
}
