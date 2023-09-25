package eddsa_test

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/eddsa"
)

func Test_MeasureConstantTime_eddsa(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := edwards25519.New()
	message := []byte("Hello")
	hashFunc := sha256.New
	messageHash, err := hashing.Hash(hashFunc, message)
	require.NoError(t, err)
	var publicKey curves.Point
	var signature *eddsa.Signature
	internal.RunMeasurement(500, "eddsa_verify", func(i int) {
		p, privateKey, err := nativeEddsa.GenerateKey(crand.Reader)
		require.NoError(t, err)
		publicKey, err = curve.Point().FromAffineCompressed(p)
		require.NoError(t, err)
		s := nativeEddsa.Sign(privateKey, messageHash)
		R, err := curve.Point().FromAffineCompressed(s[:32])
		require.NoError(t, err)
		Z, err := curve.Scalar().SetBytes(s[32:])
		require.NoError(t, err)
		signature = &eddsa.Signature{
			R: R,
			Z: Z,
		}
	}, func() {
		eddsa.Verify(curve, hashFunc, signature, publicKey, messageHash)
	})
}
