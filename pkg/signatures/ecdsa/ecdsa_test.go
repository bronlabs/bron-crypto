package ecdsa_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func Test_RecoverPublicKey(t *testing.T) {
	t.Parallel()

	nativeCurve := elliptic.P256()
	curve := p256.NewCurve()

	hashFunc := sha256.New
	message := []byte("Hello")
	messageHash, err := hashing.Hash(hashFunc, message)
	require.NoError(t, err)

	nativePrivateKey, err := nativeEcdsa.GenerateKey(nativeCurve, crand.Reader)
	require.NoError(t, err)
	nativePublicKey := &nativePrivateKey.PublicKey

	px := curve.BaseField().Element().SetNat(
		new(saferith.Nat).SetBig(nativePublicKey.X, curve.BaseField().Order().BitLen()),
	)
	py := curve.BaseField().Element().SetNat(
		new(saferith.Nat).SetBig(nativePublicKey.Y, curve.BaseField().Order().BitLen()),
	)
	publicKey, err := curve.NewPoint(px, py)
	require.NoError(t, err)

	nativeR, nativeS, err := nativeEcdsa.Sign(crand.Reader, nativePrivateKey, messageHash)
	require.NoError(t, err)

	r := curve.Scalar().SetNat(new(saferith.Nat).SetBig(nativeR, curve.SubGroupOrder().BitLen()))
	s := curve.Scalar().SetNat(new(saferith.Nat).SetBig(nativeS, curve.SubGroupOrder().BitLen()))

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
