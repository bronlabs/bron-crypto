package trusted_dealer_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/schnorr"
	trusted_dealer "github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/keygen/ed25519_trusted_dealer"
	"github.com/stretchr/testify/require"
)

type identityKey struct {
	curve *curves.Curve
	key   *schnorr.PrivateKey
}

func (k *identityKey) PublicKey() curves.Point {
	return k.key.PublicKey.Y
}
func (k *identityKey) Sign(message []byte) []byte {
	signature, err := k.key.Sign(crand.Reader, message, nil)
	if err != nil {
		panic(err)
	}
	result, err := json.Marshal(signature)
	if err != nil {
		panic(err)
	}
	return result
}

func Test_happyPath(t *testing.T) {
	t.Parallel()
	curve := curves.K256()

	aliceIdentityPrivateKey := schnorr.Keygen(curve, nil, crand.Reader)
	aliceIdentityKey := &identityKey{
		curve: curve,
		key:   aliceIdentityPrivateKey,
	}
	bobIdentityPrivateKey := schnorr.Keygen(curve, nil, crand.Reader)
	bobIdentityKey := &identityKey{
		curve: curve,
		key:   bobIdentityPrivateKey,
	}
	charlieIdentityPrivateKey := schnorr.Keygen(curve, nil, crand.Reader)
	charlieIdentityKey := &identityKey{
		curve: curve,
		key:   charlieIdentityPrivateKey,
	}

	cohortConfig := &integration.CohortConfig{
		Curve:                curve,
		Protocol:             protocol.FROST,
		Hash:                 sha512.New512_256,
		Threshold:            2,
		TotalParties:         3,
		Participants:         []integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey},
		SignatureAggregators: []integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey},
	}

	signingKeyShares, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, signingKeyShares)
	require.Len(t, signingKeyShares, cohortConfig.TotalParties)

	for _, signingKeyShare := range signingKeyShares {
		err = signingKeyShare.Validate()
		require.NoError(t, err)
	}
}
