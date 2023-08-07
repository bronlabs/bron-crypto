package trusted_dealer_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"hash"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr"
	trusted_dealer "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/keygen/ed25519_trusted_dealer"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type identityKey struct {
	curve  *curves.Curve
	signer *schnorr.Signer
	h      func() hash.Hash
}

func (k *identityKey) PublicKey() curves.Point {
	return k.signer.PublicKey.Y
}
func (k *identityKey) Hash() [32]byte {
	return sha3.Sum256(k.signer.PublicKey.Y.ToAffineCompressed())
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

func Test_happyPath(t *testing.T) {
	t.Parallel()
	curve := curves.ED25519()
	h := sha512.New

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	aliceSigner, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader, nil)
	require.NoError(t, err)
	aliceIdentityKey := &identityKey{
		curve:  curve,
		signer: aliceSigner,
		h:      h,
	}
	bobSigner, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader, nil)
	require.NoError(t, err)
	bobIdentityKey := &identityKey{
		curve:  curve,
		signer: bobSigner,
		h:      h,
	}
	charlieSigner, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader, nil)
	require.NoError(t, err)
	charlieIdentityKey := &identityKey{
		curve:  curve,
		signer: charlieSigner,
		h:      h,
	}

	cohortConfig := &integration.CohortConfig{
		CipherSuite:          cipherSuite,
		Protocol:             protocols.FROST,
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
