package ecdsa_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/internal"
	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/p256"
	"github.com/copperexchange/krypton/pkg/hashing"
	"github.com/copperexchange/krypton/pkg/signatures/ecdsa"
)

func Test_MeasureConstantTime_ecdsa(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	nativeCurve := elliptic.P256()
	curve := p256.New()

	hashFunc := sha256.New
	message := []byte("Hello")
	messageHash, err := hashing.Hash(hashFunc, message)
	require.NoError(t, err)
	var r curves.Scalar
	var s curves.Scalar
	var publicKey curves.Point

	internal.RunMeasurement(500, "ecdsa_verify", func(i int) {
		nativePrivateKey, err := nativeEcdsa.GenerateKey(nativeCurve, crand.Reader)
		require.NoError(t, err)
		nativePublicKey := &nativePrivateKey.PublicKey

		publicKey, err = curve.Point().Set(
			new(saferith.Nat).SetBig(nativePublicKey.X, curve.Profile().Field().Order().BitLen()),
			new(saferith.Nat).SetBig(nativePublicKey.Y, curve.Profile().Field().Order().BitLen()),
		)
		require.NoError(t, err)

		nativeR, nativeS, err := nativeEcdsa.Sign(crand.Reader, nativePrivateKey, messageHash)
		require.NoError(t, err)

		r, err = curve.Scalar().SetNat(new(saferith.Nat).SetBig(nativeR, curve.Profile().SubGroupOrder().BitLen()))
		require.NoError(t, err)

		s, err = curve.Scalar().SetNat(new(saferith.Nat).SetBig(nativeS, curve.Profile().SubGroupOrder().BitLen()))
		require.NoError(t, err)
	}, func() {
		for v := 0; v < 4; v++ {
			ecdsa.Verify(&ecdsa.Signature{V: &v, R: r, S: s}, hashFunc, publicKey, message)
		}
	})
}
