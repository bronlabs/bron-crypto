package noninteractive_signing

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
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
	return errs.NewMissing("not implemented")
}

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.New()
	n := 2 // By convention, all parties will have to be present for pregen ceremony.
	tau := 5
	alicePublicKey, err := curve.Point().Random(crand.Reader)
	require.NoError(t, err)
	aliceIdentityKey := &mockedIdentityKey{
		curve:     curve,
		publicKey: alicePublicKey,
	}

	bobPublicKey, err := curve.Point().Random(crand.Reader)
	require.NoError(t, err)
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
			Threshold:            n,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identityKeys),
		},
	}

	alice, err := NewPreGenParticipant(aliceIdentityKey, cohortConfig, tau, crand.Reader)
	require.NoError(t, err)
	bob, err := NewPreGenParticipant(bobIdentityKey, cohortConfig, tau, crand.Reader)
	require.NoError(t, err)
	for _, party := range []*PreGenParticipant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Equal(t, party.Tau, tau)

	}
}
