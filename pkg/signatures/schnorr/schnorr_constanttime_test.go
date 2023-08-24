package schnorr_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr"
)

func Test_MeasureConstantTime_signing(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.New(),
		Hash:  sha3.New256,
	}
	var err error
	var signer *schnorr.Signer
	message := make([]byte, 32)

	internal.RunMeasurement(500, "schnorr_signing", func(i int) {
		signer, err = schnorr.NewSigner(cipherSuite, nil, crand.Reader)
		require.NoError(t, err)
	}, func() {
		signer.Sign(message)
	})
}

func Test_MeasureConstantTime_verify(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.New(),
		Hash:  sha3.New256,
	}
	var err error
	var signer *schnorr.Signer
	message := make([]byte, 32)
	var signature *schnorr.Signature
	internal.RunMeasurement(500, "schnorr_verify", func(i int) {
		signer, err = schnorr.NewSigner(cipherSuite, nil, crand.Reader)
		require.NoError(t, err)
		signature, err = signer.Sign(message)
		require.NoError(t, err)
	}, func() {
		schnorr.Verify(cipherSuite, signer.PublicKey, message, signature)
	})
}
