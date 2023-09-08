package pedersen

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
	alice, err := NewParticipant([]byte("test"), aliceIdentityKey, cohortConfig, nil, crand.Reader)
	require.NoError(t, err)
	bob, err := NewParticipant([]byte("test"), bobIdentityKey, cohortConfig, nil, crand.Reader)
	require.NoError(t, err)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Len(t, party.SharingIdToIdentityKey, 2)
	}
	require.NotEqual(t, alice.MySharingId, bob.MySharingId)
}
