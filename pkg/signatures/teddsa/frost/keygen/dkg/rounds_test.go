package dkg_test

import (
	crand "crypto/rand"
	"encoding/json"
	"hash"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/schnorr"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/keygen/dkg"
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

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	curve := curves.ED25519()
	h := sha3.New256

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
		Protocol:             protocol.FROST,
		Threshold:            2,
		TotalParties:         3,
		Participants:         []integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey},
		SignatureAggregators: []integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey},
	}

	alice, err := dkg.NewDKGParticipant(aliceIdentityKey, cohortConfig, crand.Reader)
	require.NoError(t, err)
	bob, err := dkg.NewDKGParticipant(bobIdentityKey, cohortConfig, crand.Reader)
	require.NoError(t, err)
	charlie, err := dkg.NewDKGParticipant(charlieIdentityKey, cohortConfig, crand.Reader)
	require.NoError(t, err)

	aliceRound1Output, err := alice.Round1()
	require.NoError(t, err)
	require.NotNil(t, aliceRound1Output)
	bobRound1Output, err := bob.Round1()
	require.NoError(t, err)
	require.NotNil(t, bobRound1Output)
	charlieRound1Output, err := charlie.Round1()
	require.NoError(t, err)
	require.NotNil(t, charlieRound1Output)

	aliceRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
		bobIdentityKey:     bobRound1Output,
		charlieIdentityKey: charlieRound1Output,
	}
	bobRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
		aliceIdentityKey:   aliceRound1Output,
		charlieIdentityKey: charlieRound1Output,
	}
	charlieRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
		aliceIdentityKey: aliceRound1Output,
		bobIdentityKey:   bobRound1Output,
	}

	aliceRound2OutputBroadcast, aliceRound2OutputP2P, err := alice.Round2(aliceRound2Input)
	require.NoError(t, err)
	require.Len(t, aliceRound2OutputP2P, 2)
	bobRound2OutputBroadcast, bobRound2OutputP2P, err := bob.Round2(bobRound2Input)
	require.NoError(t, err)
	require.Len(t, bobRound2OutputP2P, 2)
	charlieRound2OutputBroadcast, charlieRound2OutputP2P, err := charlie.Round2(charlieRound2Input)
	require.NoError(t, err)
	require.Len(t, charlieRound2OutputP2P, 2)

	aliceRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
		bobIdentityKey:     bobRound2OutputBroadcast,
		charlieIdentityKey: charlieRound2OutputBroadcast,
	}
	bobRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
		aliceIdentityKey:   aliceRound2OutputBroadcast,
		charlieIdentityKey: charlieRound2OutputBroadcast,
	}
	charlieRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
		aliceIdentityKey: aliceRound2OutputBroadcast,
		bobIdentityKey:   bobRound2OutputBroadcast,
	}

	aliceRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
		bobIdentityKey:     bobRound2OutputP2P[aliceIdentityKey],
		charlieIdentityKey: charlieRound2OutputP2P[aliceIdentityKey],
	}
	bobRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
		aliceIdentityKey:   aliceRound2OutputP2P[bobIdentityKey],
		charlieIdentityKey: charlieRound2OutputP2P[bobIdentityKey],
	}
	charlieRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
		aliceIdentityKey: aliceRound2OutputP2P[charlieIdentityKey],
		bobIdentityKey:   bobRound2OutputP2P[charlieIdentityKey],
	}

	aliceSigningKeyShare, alicePublicKeyShares, err := alice.Round3(aliceRound3InputFromBroadcast, aliceRound3InputFromP2P)
	require.NoError(t, err)
	require.NotNil(t, alicePublicKeyShares)
	bobSigningKeyShare, bobPublicKeyShares, err := bob.Round3(bobRound3InputFromBroadcast, bobRound3InputFromP2P)
	require.NoError(t, err)
	require.NotNil(t, bobPublicKeyShares)
	charlieSigningKeyShare, charliePublicKeyShares, err := charlie.Round3(charlieRound3InputFromBroadcast, charlieRound3InputFromP2P)
	require.NoError(t, err)
	require.NotNil(t, charliePublicKeyShares)

	require.NotZero(t, aliceSigningKeyShare.Share.Cmp(bobSigningKeyShare.Share))
	require.NotZero(t, aliceSigningKeyShare.Share.Cmp(charlieSigningKeyShare.Share))
	require.NotZero(t, bobSigningKeyShare.Share.Cmp(aliceSigningKeyShare.Share))
	require.NotZero(t, bobSigningKeyShare.Share.Cmp(charlieSigningKeyShare.Share))
	require.NotZero(t, charlieSigningKeyShare.Share.Cmp(aliceSigningKeyShare.Share))
	require.NotZero(t, charlieSigningKeyShare.Share.Cmp(bobSigningKeyShare.Share))

	require.True(t, aliceSigningKeyShare.PublicKey.Equal(bobSigningKeyShare.PublicKey))
	require.True(t, aliceSigningKeyShare.PublicKey.Equal(charlieSigningKeyShare.PublicKey))
	require.True(t, bobSigningKeyShare.PublicKey.Equal(charlieSigningKeyShare.PublicKey))

	shamirDealer, err := sharing.NewShamir(2, 3, curve)
	require.NoError(t, err)
	require.NotNil(t, shamirDealer)

	aliceShamirShare := &sharing.ShamirShare{
		Id:    uint32(alice.MyShamirId),
		Value: aliceSigningKeyShare.Share.Bytes(),
	}
	bobShamirShare := &sharing.ShamirShare{
		Id:    uint32(bob.MyShamirId),
		Value: bobSigningKeyShare.Share.Bytes(),
	}
	charlieShamirShare := &sharing.ShamirShare{
		Id:    uint32(charlie.MyShamirId),
		Value: charlieSigningKeyShare.Share.Bytes(),
	}

	reconstructedPrivateKey, err := shamirDealer.Combine(aliceShamirShare, bobShamirShare, charlieShamirShare)
	require.NoError(t, err)

	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)

	require.True(t, aliceSigningKeyShare.PublicKey.Equal(derivedPublicKey))
}
