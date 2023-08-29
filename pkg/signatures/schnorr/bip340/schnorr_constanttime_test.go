package bip340_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr/bip340"
)

func Test_MeasureConstantTime_signing(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	var signer *bip340.Signer

	aux := make([]byte, 32)
	_, _ = crand.Read(aux)
	message := make([]byte, 32)
	curve := k256.New()

	internal.RunMeasurement(500, "bip340_signing", func(i int) {
		privateKey, err := bip340.NewPrivateKey(curve.Scalar().Random(crand.Reader))
		require.NoError(t, err)
		signer = bip340.NewSigner(privateKey)

	}, func() {
		_, _ = signer.Sign(message, aux, nil)
	})
}

func Test_MeasureConstantTime_verify(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	var err error
	var signer *bip340.Signer
	var privateKey *bip340.PrivateKey
	var signature *bip340.Signature

	aux := make([]byte, 32)
	_, _ = crand.Read(aux)
	message := make([]byte, 32)
	curve := k256.New()

	internal.RunMeasurement(500, "bip340_verify", func(i int) {
		privateKey, err = bip340.NewPrivateKey(curve.Scalar().Random(crand.Reader))
		require.NoError(t, err)
		signer = bip340.NewSigner(privateKey)
		signature, err = signer.Sign(message, aux, nil)
		require.NoError(t, err)
	}, func() {
		err = bip340.Verify(&privateKey.PublicKey, signature, message)
	})
}

func Test_MeasureConstantTime_batchverify(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	var err error
	var signer *bip340.Signer
	var signature *bip340.Signature
	var privateKey *bip340.PrivateKey

	aux := make([]byte, 32)
	_, _ = crand.Read(aux)
	message := make([]byte, 32)
	curve := k256.New()

	internal.RunMeasurement(500, "bip340_batchverify", func(i int) {
		privateKey, err = bip340.NewPrivateKey(curve.Scalar().Random(crand.Reader))
		require.NoError(t, err)
		signer = bip340.NewSigner(privateKey)
		require.NoError(t, err)
		signature, err = signer.Sign(message, aux, nil)
		require.NoError(t, err)
	}, func() {
		_ = bip340.VerifyBatch([]*bip340.PublicKey{&privateKey.PublicKey}, []*bip340.Signature{signature}, [][]byte{message}, crand.Reader)
	})
}
