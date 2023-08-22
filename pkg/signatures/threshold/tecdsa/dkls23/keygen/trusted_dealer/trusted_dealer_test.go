package trusted_dealer_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"hash"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/keygen/trusted_dealer"
	"github.com/stretchr/testify/require"
)

type identityKey struct {
	curve  curves.Curve
	signer *schnorr.Signer
	h      func() hash.Hash

	_ helper_types.Incomparable
}

func (k *identityKey) PublicKey() curves.Point {
	return k.signer.PublicKey.Y
}
func (k *identityKey) Sign(message []byte) []byte {
	signature, err := k.signer.Sign(message)
	if err != nil {
		panic(err)
	}
	result, err := json.Marshal(signature)
	if err != nil {
		panic(err)
	}
	return result
}
func (k *identityKey) Verify(signature []byte, publicKey curves.Point, message []byte) error {
	return errors.New("not implemented")
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	curve := k256.New()
	h := sha256.New
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}
	th := 2
	n := 3

	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	alice, bob, charlie := identities[0], identities[1], identities[2]

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet([]integration.IdentityKey{alice, bob, charlie}),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.DKLS23,
			Threshold:            2,
			TotalParties:         3,
			SignatureAggregators: hashset.NewHashSet([]integration.IdentityKey{alice, bob, charlie}),
		},
	}

	shards, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shards)
	require.Len(t, shards, cohortConfig.Protocol.TotalParties)

	t.Run("all signing key shares are valid", func(t *testing.T) {
		t.Parallel()
		for _, shard := range shards {
			err = shard.SigningKeyShare.Validate()
			require.NoError(t, err)
		}
	})

	t.Run("all public keys are the same", func(t *testing.T) {
		t.Parallel()
		publicKeys := map[curves.Point]bool{}
		for _, shard := range shards {
			if _, exists := publicKeys[shard.SigningKeyShare.PublicKey]; !exists {
				publicKeys[shard.SigningKeyShare.PublicKey] = true
			}
		}
		require.Len(t, publicKeys, 1)
	})

	t.Run("all signing key shares interpolate to dlog of public key", func(t *testing.T) {
		t.Parallel()

		shamirDealer, err := shamir.NewDealer(th, n, curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, n)
		for i := 0; i < 3; i++ {
			shamirShares[i] = &shamir.Share{
				Id:    i + 1,
				Value: shards[identities[i].Hash()].SigningKeyShare.Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		require.True(t, shards[identities[0].Hash()].SigningKeyShare.PublicKey.Equal(derivedPublicKey))
	})
}
