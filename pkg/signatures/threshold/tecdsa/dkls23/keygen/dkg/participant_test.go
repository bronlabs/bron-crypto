package dkg

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	agreeonrandom_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/pkg/errors"
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
		Protocol:             protocol.DKLS23,
		Threshold:            2,
		TotalParties:         2,
		Participants:         identityKeys,
		SignatureAggregators: identityKeys,
	}
	identities := []integration.IdentityKey{aliceIdentityKey, bobIdentityKey}
	pedersenSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, 2)
	zeroSamplingSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, 2)
	alice, err := NewParticipant(aliceIdentityKey, pedersenSessionId, zeroSamplingSessionId, cohortConfig, crand.Reader)
	bob, err := NewParticipant(bobIdentityKey, pedersenSessionId, zeroSamplingSessionId, cohortConfig, crand.Reader)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.NotNil(t, party)
	}
	require.NotEqual(t, alice.GetShamirId(), bob.GetShamirId())
}
