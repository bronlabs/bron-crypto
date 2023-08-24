package bip340_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr/bip340"
)

func Test_MeasureConstantTime_signing(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha3.New256,
	}
	aux := make([]byte, 32)
	_, _ = crand.Read(aux)
	var err error
	var signer *bip340.Signer
	message := make([]byte, 32)

	internal.RunMeasurement(500, "bip340_signing", func(i int) {
		signer, err = bip340.NewSigner(cipherSuite, k256.New().Scalar().Random(crand.Reader))
		require.NoError(t, err)
	}, func() {
		signer.Sign(message, nil)
	})
}

func Test_MeasureConstantTime_verify(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha3.New256,
	}
	aux := make([]byte, 32)
	_, _ = crand.Read(aux)
	var err error
	var signer *bip340.Signer
	message := make([]byte, 32)
	var signature *bip340.Signature

	internal.RunMeasurement(500, "bip340_verify", func(i int) {
		signer, err = bip340.NewSigner(cipherSuite, k256.New().Scalar().Random(crand.Reader))
		require.NoError(t, err)
		signature, err = signer.Sign(message, nil)
		require.NoError(t, err)
	}, func() {
		err = bip340.Verify(signer.PublicKey, message, signature)
	})
}

func Test_MeasureConstantTime_batchverify(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha3.New256,
	}
	aux := make([]byte, 32)
	_, _ = crand.Read(aux)
	var err error
	var signer *bip340.Signer
	message := make([]byte, 32)
	var signature *bip340.Signature
	internal.RunMeasurement(500, "bip340_batchverify", func(i int) {
		signer, err = bip340.NewSigner(cipherSuite, k256.New().Scalar().Random(crand.Reader))
		require.NoError(t, err)
		signature, err = signer.Sign(message, nil)
		require.NoError(t, err)
	}, func() {
		bip340.BatchVerify(nil, cipherSuite, []*bip340.PublicKey{signer.PublicKey}, [][]byte{message}, []*bip340.Signature{signature})
	})
}
