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

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
)

func Test_MeasureConstantTime_ecdsa(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	nativeCurve := elliptic.P256()
	curve := p256.NewCurve()

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

		publicKey, err = curve.NewPoint(
			curve.BaseField().Element().SetNat(new(saferith.Nat).SetBig(nativePublicKey.X, curve.BaseField().Order().BitLen())),
			curve.BaseField().Element().SetNat(new(saferith.Nat).SetBig(nativePublicKey.Y, curve.BaseField().Order().BitLen())),
		)
		require.NoError(t, err)

		nativeR, nativeS, err := nativeEcdsa.Sign(crand.Reader, nativePrivateKey, messageHash)
		require.NoError(t, err)

		r = curve.Scalar().SetNat(new(saferith.Nat).SetBig(nativeR, curve.SubGroupOrder().BitLen()))
		s = curve.Scalar().SetNat(new(saferith.Nat).SetBig(nativeS, curve.SubGroupOrder().BitLen()))
	}, func() {
		for v := 0; v < 4; v++ {
			ecdsa.Verify(&ecdsa.Signature{V: &v, R: r, S: s}, hashFunc, publicKey, message)
		}
	})
}
