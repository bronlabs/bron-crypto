package ecdsa_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
)

func Test_RecoverPublicKey(t *testing.T) {
	t.Parallel()

	nativeCurve := elliptic.P256()
	curve := p256.New()

	hashFunc := sha256.New
	message := []byte("Hello")
	messageHash, err := hashing.Hash(hashFunc, message)
	require.NoError(t, err)

	nativePrivateKey, err := nativeEcdsa.GenerateKey(nativeCurve, crand.Reader)
	require.NoError(t, err)
	nativePublicKey := &nativePrivateKey.PublicKey

	publicKey, err := curve.Point().Set(
		new(saferith.Nat).SetBig(nativePublicKey.X, curve.Profile().Field().Order().BitLen()),
		new(saferith.Nat).SetBig(nativePublicKey.Y, curve.Profile().Field().Order().BitLen()),
	)
	require.NoError(t, err)

	nativeR, nativeS, err := nativeEcdsa.Sign(crand.Reader, nativePrivateKey, messageHash)
	require.NoError(t, err)

	r, err := curve.Scalar().SetNat(new(saferith.Nat).SetBig(nativeR, curve.Profile().SubGroupOrder().BitLen()))
	require.NoError(t, err)

	s, err := curve.Scalar().SetNat(new(saferith.Nat).SetBig(nativeS, curve.Profile().SubGroupOrder().BitLen()))
	require.NoError(t, err)

	ok := nativeEcdsa.Verify(nativePublicKey, messageHash, nativeR, nativeS)
	require.True(t, ok)

	// Note, we don't have a RecoveryId here, so we check all four possibilities
	// and one of them shall match
	successfullyRecoveredValidPublicKey := false
	for v := 0; v < 4; v++ {
		if err := ecdsa.Verify(&ecdsa.Signature{V: &v, R: r, S: s}, hashFunc, publicKey, message); err == nil {
			successfullyRecoveredValidPublicKey = true
			break
		}
	}
	require.True(t, successfullyRecoveredValidPublicKey)
}
