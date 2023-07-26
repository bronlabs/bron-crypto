package ecdsa_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/hashing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/ecdsa"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_VerifyAndRecovery(t *testing.T) {
	t.Parallel()

	hashFunc := sha256.New
	message := []byte("Hello")
	messageHash, err := hashing.Hash(hashFunc, message)
	require.NoError(t, err)

	nativePrivateKey, err := nativeEcdsa.GenerateKey(elliptic.P256(), crand.Reader)
	require.NoError(t, err)
	nativePublicKey := &nativePrivateKey.PublicKey

	nativeR, nativeS, err := nativeEcdsa.Sign(crand.Reader, nativePrivateKey, messageHash)
	require.NoError(t, err)

	ok := nativeEcdsa.Verify(nativePublicKey, messageHash, nativeR, nativeS)
	require.True(t, ok)

	knoxSignature, err := new(ecdsa.Signature).FromNative(nativePublicKey.Curve, nativeR, nativeS)
	require.NoError(t, err)

	// Note, we don't have a RecoveryId here, so we check all four possibilities
	// and one of them shall match
	ok0 := knoxSignature.VerifyMessageWithRecoveryId(&ecdsa.RecoveryId{V: 0}, hashFunc, message)
	ok1 := knoxSignature.VerifyMessageWithRecoveryId(&ecdsa.RecoveryId{V: 1}, hashFunc, message)
	ok2 := knoxSignature.VerifyMessageWithRecoveryId(&ecdsa.RecoveryId{V: 2}, hashFunc, message)
	ok3 := knoxSignature.VerifyMessageWithRecoveryId(&ecdsa.RecoveryId{V: 3}, hashFunc, message)
	require.True(t, ok0 || ok1 || ok2 || ok3)
}
