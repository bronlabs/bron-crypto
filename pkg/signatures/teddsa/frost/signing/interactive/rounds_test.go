package interactive_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"hash"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/schnorr"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/keygen/dkg"
	interactive_signing "github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/interactive"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
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
func (k *identityKey) Verify(signature []byte, publicKey curves.Point, message []byte) error {
	return errors.New("not implemented")
}

func Test_HappyPath(t *testing.T) {
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
		Protocol:             protocol.FROST,
		Threshold:            2,
		TotalParties:         3,
		Participants:         []integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey},
		SignatureAggregators: []integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey},
	}

	aliceDkg, err := dkg.NewDKGParticipant(aliceIdentityKey, cohortConfig, crand.Reader)
	require.NoError(t, err)
	bobDkg, err := dkg.NewDKGParticipant(bobIdentityKey, cohortConfig, crand.Reader)
	require.NoError(t, err)
	charlieDkg, err := dkg.NewDKGParticipant(charlieIdentityKey, cohortConfig, crand.Reader)
	require.NoError(t, err)

	aliceDkgRound1Output, err := aliceDkg.Round1()
	require.NoError(t, err)
	bobDkgRound1Output, err := bobDkg.Round1()
	require.NoError(t, err)
	charlieDkgRound1Output, err := charlieDkg.Round1()
	require.NoError(t, err)

	aliceDkgRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
		bobIdentityKey:     bobDkgRound1Output,
		charlieIdentityKey: charlieDkgRound1Output,
	}
	bobDkgRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
		aliceIdentityKey:   aliceDkgRound1Output,
		charlieIdentityKey: charlieDkgRound1Output,
	}
	charlieDkgRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
		aliceIdentityKey: aliceDkgRound1Output,
		bobIdentityKey:   bobDkgRound1Output,
	}

	aliceDkgRound2OutputBroadcast, aliceRound2OutputP2P, err := aliceDkg.Round2(aliceDkgRound2Input)
	require.NoError(t, err)
	bobDkgRound2OutputBroadcast, bobRound2OutputP2P, err := bobDkg.Round2(bobDkgRound2Input)
	require.NoError(t, err)
	charlieDkgRound2OutputBroadcast, charlieRound2OutputP2P, err := charlieDkg.Round2(charlieDkgRound2Input)
	require.NoError(t, err)

	aliceDkgRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
		bobIdentityKey:     bobDkgRound2OutputBroadcast,
		charlieIdentityKey: charlieDkgRound2OutputBroadcast,
	}
	bobDkgRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
		aliceIdentityKey:   aliceDkgRound2OutputBroadcast,
		charlieIdentityKey: charlieDkgRound2OutputBroadcast,
	}
	charlieDkgRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
		aliceIdentityKey: aliceDkgRound2OutputBroadcast,
		bobIdentityKey:   bobDkgRound2OutputBroadcast,
	}

	aliceDkgRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
		bobIdentityKey:     bobRound2OutputP2P[aliceIdentityKey],
		charlieIdentityKey: charlieRound2OutputP2P[aliceIdentityKey],
	}
	bobDkgRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
		aliceIdentityKey:   aliceRound2OutputP2P[bobIdentityKey],
		charlieIdentityKey: charlieRound2OutputP2P[bobIdentityKey],
	}
	charlieDkgRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
		aliceIdentityKey: aliceRound2OutputP2P[charlieIdentityKey],
		bobIdentityKey:   bobRound2OutputP2P[charlieIdentityKey],
	}

	aliceSigningKeyShare, alicePublicKeyShares, err := aliceDkg.Round3(aliceDkgRound3InputFromBroadcast, aliceDkgRound3InputFromP2P)
	require.NoError(t, err)
	require.NotNil(t, alicePublicKeyShares)
	bobSigningKeyShare, bobPublicKeyShares, err := bobDkg.Round3(bobDkgRound3InputFromBroadcast, bobDkgRound3InputFromP2P)
	require.NoError(t, err)
	require.NotNil(t, bobPublicKeyShares)
	_, charliePublicKeyShares, err := charlieDkg.Round3(charlieDkgRound3InputFromBroadcast, charlieDkgRound3InputFromP2P)
	require.NoError(t, err)
	require.NotNil(t, charliePublicKeyShares)

	publicKey := aliceSigningKeyShare.PublicKey
	message := []byte("something")

	aliceSessionParticipants := []integration.IdentityKey{aliceIdentityKey, bobIdentityKey}
	bobSessionParticipants := []integration.IdentityKey{aliceIdentityKey, bobIdentityKey}

	alice, err := interactive_signing.NewInteractiveCosigner(aliceIdentityKey, aliceSessionParticipants, aliceSigningKeyShare, alicePublicKeyShares, cohortConfig, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := interactive_signing.NewInteractiveCosigner(bobIdentityKey, bobSessionParticipants, bobSigningKeyShare, bobPublicKeyShares, cohortConfig, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, bob)

	aliceRound1Output, err := alice.Round1()
	require.NoError(t, err)
	bobRound1Output, err := bob.Round1()
	require.NoError(t, err)

	aliceRound2Input := map[integration.IdentityKey]*interactive_signing.Round1Broadcast{
		bobIdentityKey: bobRound1Output,
	}
	bobRound2Input := map[integration.IdentityKey]*interactive_signing.Round1Broadcast{
		aliceIdentityKey: aliceRound1Output,
	}

	alicePartialSignature, err := alice.Round2(aliceRound2Input, message)
	require.NoError(t, err)
	bobPartialSignature, err := bob.Round2(bobRound2Input, message)
	require.NoError(t, err)

	partialSignatures := map[integration.IdentityKey]*frost.PartialSignature{
		aliceIdentityKey: alicePartialSignature,
		bobIdentityKey:   bobPartialSignature,
	}

	aliceSignature, err := alice.Aggregate(message, partialSignatures)
	require.NoError(t, err)
	bobSignature, err := bob.Aggregate(message, partialSignatures)
	require.NoError(t, err)

	for _, signature := range []*frost.Signature{aliceSignature, bobSignature} {
		aliceVerificationResult := frost.Verify(curve, cohortConfig.CipherSuite.Hash, signature, publicKey, message)
		require.NoError(t, aliceVerificationResult)
		bobVerificationResult := frost.Verify(curve, cohortConfig.CipherSuite.Hash, signature, publicKey, message)
		require.NoError(t, bobVerificationResult)
		charlieVerificationResult := frost.Verify(curve, cohortConfig.CipherSuite.Hash, signature, publicKey, message)
		require.NoError(t, charlieVerificationResult)
	}
}
