package eddsa_test

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha512"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures/eddsa"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/vanilla"
)

func Test_MeasureConstantTime_eddsa(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := edwards25519.NewCurve()
	message := []byte("Hello")
	hashFunc := sha512.New

	messageHash, err := hashing.Hash(hashFunc, message)
	require.NoError(t, err)
	var publicKey curves.Point
	var signature *eddsa.Signature
	internal.RunMeasurement(500, "eddsa_verify", func(i int) {
		p, privateKey, err := nativeEddsa.GenerateKey(crand.Reader)
		require.NoError(t, err)
		publicKey, err = curve.Point().FromAffineCompressed(p)
		require.NoError(t, err)
		sig := nativeEddsa.Sign(privateKey, messageHash)
		R, err := curve.Point().FromAffineCompressed(sig[:32])
		require.NoError(t, err)
		s, err := curve.Scalar().SetBytes(sig[32:])
		require.NoError(t, err)
		signature = schnorr.NewSignature(vanilla.NewEdDsaCompatibleVariant(), nil, R, s)
	}, func() {
		eddsa.Verify(&eddsa.PublicKey{A: publicKey}, messageHash, signature)
	})
}
