package trusted_dealer_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"hash"
	"testing"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton/pkg/base/protocols"
	"github.com/copperexchange/krypton/pkg/signatures/schnorr"
	trusted_dealer "github.com/copperexchange/krypton/pkg/threshold/tsignatures/tschnorr/frost/keygen/ed25519_trusted_dealer"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type identityKey struct {
	curve  curves.Curve
	signer *schnorr.Signer
	h      func() hash.Hash

	_ types.Incomparable
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
	curve := edwards25519.New()
	h := sha512.New

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	aliceSigner, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader)
	require.NoError(t, err)
	aliceIdentityKey := &identityKey{
		curve:  curve,
		signer: aliceSigner,
		h:      h,
	}
	bobSigner, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader)
	require.NoError(t, err)
	bobIdentityKey := &identityKey{
		curve:  curve,
		signer: bobSigner,
		h:      h,
	}
	charlieSigner, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader)
	require.NoError(t, err)
	charlieIdentityKey := &identityKey{
		curve:  curve,
		signer: charlieSigner,
		h:      h,
	}

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet([]integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey}),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.FROST,
			Threshold:            2,
			TotalParties:         3,
			SignatureAggregators: hashset.NewHashSet([]integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey}),
		},
	}

	signingKeyShares, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, signingKeyShares)
	require.Len(t, signingKeyShares, cohortConfig.Protocol.TotalParties)

	for _, signingKeyShare := range signingKeyShares {
		err = signingKeyShare.Validate()
		require.NoError(t, err)
	}
}
