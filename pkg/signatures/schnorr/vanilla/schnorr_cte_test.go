package schnorr_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

func Test_MeasureConstantTime_signing(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.NewCurve(),
		Hash:  sha3.New256,
	}
	var err error
	var signer *schnorr.Signer
	var sk *schnorr.PrivateKey
	message := make([]byte, 32)

	internal.RunMeasurement(500, "schnorr_signing", func(i int) {
		_, sk, err = schnorr.KeyGen(cipherSuite.Curve, crand.Reader)
		require.NoError(t, err)
		signer, err = schnorr.NewSigner(cipherSuite, sk)
		require.NoError(t, err)
	}, func() {
		signer.Sign(message, crand.Reader)
	})
}

func Test_MeasureConstantTime_verify(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.NewCurve(),
		Hash:  sha3.New256,
	}
	var err error
	var signer *schnorr.Signer
	var pk *schnorr.PublicKey
	var sk *schnorr.PrivateKey
	message := make([]byte, 32)
	var signature *schnorr.Signature
	internal.RunMeasurement(500, "schnorr_verify", func(i int) {
		pk, sk, err = schnorr.KeyGen(cipherSuite.Curve, crand.Reader)
		require.NoError(t, err)
		signer, err = schnorr.NewSigner(cipherSuite, sk)
		require.NoError(t, err)
		signature, err = signer.Sign(message, crand.Reader)
		require.NoError(t, err)
	}, func() {
		schnorr.Verify(cipherSuite, pk, message, signature)
	})
}
