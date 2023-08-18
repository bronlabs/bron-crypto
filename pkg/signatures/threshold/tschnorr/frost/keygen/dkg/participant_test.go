package dkg

import (
	crand "crypto/rand"
	"crypto/sha512"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"testing"

	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type mockedIdentityKey struct {
	curve     curves.Curve
	publicKey curves.Point

	_ helper_types.Incomparable
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
		CipherSuite:          cipherSuite,
		Protocol:             protocols.FROST,
		Threshold:            2,
		TotalParties:         2,
		Participants:         hashset.NewHashSet(identityKeys),
		SignatureAggregators: hashset.NewHashSet(identityKeys),
	}
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identityKeys)
	require.NoError(t, err)
	alice, err := NewParticipant(uniqueSessionId, aliceIdentityKey, cohortConfig, crand.Reader)
	bob, err := NewParticipant(uniqueSessionId, bobIdentityKey, cohortConfig, crand.Reader)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.NotNil(t, party)
	}
	require.NotEqual(t, alice.GetSharingId(), bob.GetSharingId())
}
