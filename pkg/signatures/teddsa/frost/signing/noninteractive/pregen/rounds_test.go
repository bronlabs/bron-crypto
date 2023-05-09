package pregen_test

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
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/noninteractive/pregen"
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
	cipherSuite := &integration.CipherSuite{
		Curve: k.curve,
		Hash:  k.h,
	}
	schnorrSignature := &schnorr.Signature{}
	if err := json.Unmarshal(signature, &schnorrSignature); err != nil {
		return errors.Wrap(err, "could not unmarshal signature")
	}
	schnorrPublicKey := &schnorr.PublicKey{
		Curve: k.curve,
		Y:     k.PublicKey(),
	}
	if err := schnorr.Verify(cipherSuite, schnorrPublicKey, message, schnorrSignature, nil); err != nil {
		return errors.Wrap(err, "could not verify schnorr signature")
	}
	return nil
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

	tau := 5

	alice, err := pregen.NewPreGenParticipant(aliceIdentityKey, cohortConfig, tau, crand.Reader)
	require.NoError(t, err)
	bob, err := pregen.NewPreGenParticipant(bobIdentityKey, cohortConfig, tau, crand.Reader)
	require.NoError(t, err)
	charlie, err := pregen.NewPreGenParticipant(charlieIdentityKey, cohortConfig, tau, crand.Reader)
	require.NoError(t, err)

	aliceRound1Output, err := alice.Round1()
	require.NoError(t, err)
	bobRound1Output, err := bob.Round1()
	require.NoError(t, err)
	charlieRound1Output, err := charlie.Round1()
	require.NoError(t, err)

	aliceRound2Input := map[integration.IdentityKey]*pregen.Round1Broadcast{
		bobIdentityKey:     bobRound1Output,
		charlieIdentityKey: charlieRound1Output,
	}
	bobRound2Input := map[integration.IdentityKey]*pregen.Round1Broadcast{
		aliceIdentityKey:   aliceRound1Output,
		charlieIdentityKey: charlieRound1Output,
	}
	charlieRound2Input := map[integration.IdentityKey]*pregen.Round1Broadcast{
		aliceIdentityKey: aliceRound1Output,
		bobIdentityKey:   bobRound1Output,
	}

	alicePreSignatures, alicePrivateNoncePairs, err := alice.Round2(aliceRound2Input)
	require.NoError(t, err)
	require.NotNil(t, alicePrivateNoncePairs)
	bobPreSignatures, bobPrivateNoncePairs, err := bob.Round2(bobRound2Input)
	require.NoError(t, err)
	require.NotNil(t, bobPrivateNoncePairs)
	charliePreSignatures, charliePrivateNoncePairs, err := charlie.Round2(charlieRound2Input)
	require.NoError(t, err)
	require.NotNil(t, charliePrivateNoncePairs)

	require.Equal(t, alicePreSignatures, bobPreSignatures)
	require.Equal(t, alicePreSignatures, charliePreSignatures)
}
