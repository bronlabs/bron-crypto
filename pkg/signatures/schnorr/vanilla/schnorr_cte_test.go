package vanilla_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

func Test_MeasureConstantTime_signing(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := edwards25519.NewCurve()
	h := sha512.New
	cipherSuite, err := testutils.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	var signer *schnorr.Signer
	var sk *schnorr.PrivateKey
	message := make([]byte, 32)

	internal.RunMeasurement(500, "schnorr_signing", func(i int) {
		_, sk, err = schnorr.KeyGen(cipherSuite.Curve(), crand.Reader)
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

	curve := edwards25519.NewCurve()
	h := sha512.New
	cipherSuite, err := testutils.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	var signer *schnorr.Signer
	var pk *schnorr.PublicKey
	var sk *schnorr.PrivateKey
	message := make([]byte, 32)
	var signature *schnorr.Signature
	internal.RunMeasurement(500, "schnorr_verify", func(i int) {
		pk, sk, err = schnorr.KeyGen(cipherSuite.Curve(), crand.Reader)
		require.NoError(t, err)
		signer, err = schnorr.NewSigner(cipherSuite, sk)
		require.NoError(t, err)
		signature, err = signer.Sign(message, crand.Reader)
		require.NoError(t, err)
	}, func() {
		schnorr.Verify(cipherSuite, pk, message, signature)
	})
}
