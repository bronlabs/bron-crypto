package dkg

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
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
)

var _ integration.IdentityKey = (*mockedIdentityKey)(nil)

func (k *mockedIdentityKey) PrivateKey() curves.Scalar {
	panic("this should not be called")
}

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
			Name:                 protocols.DKLS23,
			Threshold:            2,
			TotalParties:         2,
			SignatureAggregators: hashset.NewHashSet(identityKeys),
		},
	}
	identities := []integration.IdentityKey{aliceIdentityKey, bobIdentityKey}
	sid, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)
	alice, err := NewParticipant(sid, aliceIdentityKey, cohortConfig, crand.Reader, nil)
	require.NoError(t, err)
	bob, err := NewParticipant(sid, bobIdentityKey, cohortConfig, crand.Reader, nil)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.NotNil(t, party)
	}
	require.NotEqual(t, alice.GetSharingId(), bob.GetSharingId())
}
