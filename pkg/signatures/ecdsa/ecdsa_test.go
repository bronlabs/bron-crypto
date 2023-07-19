package ecdsa_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/ecdsa"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_VerifyAndRecovery(t *testing.T) {
	t.Parallel()

	message := []byte("Hello")
	digest := sha256.Sum256(message)

	nativePrivateKey, err := nativeEcdsa.GenerateKey(elliptic.P256(), crand.Reader)
	require.NoError(t, err)
	nativePublicKey := &nativePrivateKey.PublicKey

	nativeR, nativeS, err := nativeEcdsa.Sign(crand.Reader, nativePrivateKey, digest[:])
	require.NoError(t, err)

	ok := nativeEcdsa.Verify(nativePublicKey, digest[:], nativeR, nativeS)
	require.True(t, ok)

	knoxSignature, err := new(ecdsa.Signature).FromNative(nativePublicKey.Curve, nativeR, nativeS)
	require.NoError(t, err)

	// Note, we don't have a RecoveryId here, so we check all four possibilities
	// and one of them shall match
	ok0 := knoxSignature.VerifyHashWithRecoveryId(&ecdsa.RecoveryId{V: 0}, digest[:])
	ok1 := knoxSignature.VerifyHashWithRecoveryId(&ecdsa.RecoveryId{V: 1}, digest[:])
	ok2 := knoxSignature.VerifyHashWithRecoveryId(&ecdsa.RecoveryId{V: 2}, digest[:])
	ok3 := knoxSignature.VerifyHashWithRecoveryId(&ecdsa.RecoveryId{V: 3}, digest[:])
	require.True(t, ok0 || ok1 || ok2 || ok3)
}
