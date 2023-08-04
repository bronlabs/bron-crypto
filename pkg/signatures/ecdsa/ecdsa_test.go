package ecdsa_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/hashing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/ecdsa"
	"github.com/stretchr/testify/require"
)

func Test_RecoverPublicKey(t *testing.T) {
	t.Parallel()

	nativeCurve := elliptic.P256()
	curve, err := curves.GetCurveByName(nativeCurve.Params().Name)
	require.NoError(t, err)

	hashFunc := sha256.New
	message := []byte("Hello")
	messageHash, err := hashing.Hash(hashFunc, message)
	require.NoError(t, err)

	nativePrivateKey, err := nativeEcdsa.GenerateKey(nativeCurve, crand.Reader)
	require.NoError(t, err)
	nativePublicKey := &nativePrivateKey.PublicKey

	publicKey, err := curve.Point.Set(nativePublicKey.X, nativePublicKey.Y)
	require.NoError(t, err)

	nativeR, nativeS, err := nativeEcdsa.Sign(crand.Reader, nativePrivateKey, messageHash)
	require.NoError(t, err)

	r, err := curve.Scalar.SetBigInt(nativeR)
	require.NoError(t, err)

	s, err := curve.Scalar.SetBigInt(nativeS)
	require.NoError(t, err)

	ok := nativeEcdsa.Verify(nativePublicKey, messageHash, nativeR, nativeS)
	require.True(t, ok)

	// Note, we don't have a RecoveryId here, so we check all four possibilities
	// and one of them shall match
	successfullyRecoveredValidPublicKey := false
	for v := 0; v < 4; v++ {
		if err := ecdsa.Verify(&ecdsa.Signature{&v, r, s}, hashFunc, publicKey, message); err == nil {
			successfullyRecoveredValidPublicKey = true
			break
		}
	}
	require.True(t, successfullyRecoveredValidPublicKey)
}
