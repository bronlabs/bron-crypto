package dkg

import (
	crand "crypto/rand"
	"crypto/sha512"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"testing"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton/pkg/base/protocols"
	agreeonrandom_testutils "github.com/copperexchange/krypton/pkg/threshold/agreeonrandom/testutils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
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
			Name:                 protocols.DKLS23,
			Threshold:            2,
			TotalParties:         2,
			SignatureAggregators: hashset.NewHashSet(identityKeys),
		},
	}
	identities := []integration.IdentityKey{aliceIdentityKey, bobIdentityKey}
	sid, err := agreeonrandom_testutils.ProduceSharedRandomValue(curve, identities, crand.Reader)
	require.NoError(t, err)
	alice, err := NewParticipant(sid, aliceIdentityKey, cohortConfig, crand.Reader, nil)
	bob, err := NewParticipant(sid, bobIdentityKey, cohortConfig, crand.Reader, nil)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.NotNil(t, party)
	}
	require.NotEqual(t, alice.GetSharingId(), bob.GetSharingId())
}
