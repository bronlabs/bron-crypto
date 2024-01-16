package schnorr_test

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	message := []byte("something")
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
		edwards25519.NewCurve(),
	}
	hs := []func() hash.Hash{
		sha3.New256,
		sha512.New,
	}
	for _, curve := range curveInstances {
		for i, h := range hs {
			boundedCurve := curve
			boundedH := h
			t.Run(fmt.Sprintf("running the test for curve %s and hash no %d", boundedCurve.Name(), i), func(t *testing.T) {
				t.Parallel()
				cipherSuite := &integration.CipherSuite{
					Curve: boundedCurve,
					Hash:  boundedH,
				}
				publicKey, privateKey, err := schnorr.KeyGen(cipherSuite.Curve, crand.Reader)
				require.NoError(t, err)

				signer, err := schnorr.NewSigner(cipherSuite, privateKey)
				require.NoError(t, err)
				require.NotNil(t, signer)

				signature, err := signer.Sign(message, crand.Reader)
				require.NoError(t, err)

				err = schnorr.Verify(cipherSuite, publicKey, message, signature)
				require.NoError(t, err)
			})
		}
	}
}

func Test_HappyPathWithEd25519Verifier(t *testing.T) {
	t.Parallel()
	message := []byte("something")

	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.NewCurve(),
		Hash:  sha512.New,
	}
	publicKey, privateKey, err := schnorr.KeyGen(cipherSuite.Curve, crand.Reader)
	require.NoError(t, err)

	signer, err := schnorr.NewSigner(cipherSuite, privateKey)
	require.NoError(t, err)
	require.NotNil(t, signer)

	signature, err := signer.Sign(message, crand.Reader)
	require.NoError(t, err)

	nativeSignature := bytes.Join([][]byte{signature.R.ToAffineCompressed(), bitstring.ReverseBytes(signature.S.Bytes())}, nil)
	ok := ed25519.Verify(publicKey.A.ToAffineCompressed(), message, nativeSignature)
	require.True(t, ok)
}

func Test_InvalidMessageOrSignatureFailure(t *testing.T) {
	t.Parallel()
	message := []byte("something")
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
		edwards25519.NewCurve(),
	}
	hs := []func() hash.Hash{
		sha3.New256,
		sha512.New,
	}
	for _, curve := range curveInstances {
		for i, h := range hs {
			boundedCurve := curve
			boundedH := h
			t.Run(fmt.Sprintf("running the test for curve %s and hash no %d", boundedCurve.Name(), i), func(t *testing.T) {
				t.Parallel()
				cipherSuite := &integration.CipherSuite{
					Curve: boundedCurve,
					Hash:  boundedH,
				}
				publicKey, privateKey, err := schnorr.KeyGen(cipherSuite.Curve, crand.Reader)
				require.NoError(t, err)

				signer, err := schnorr.NewSigner(cipherSuite, privateKey)
				require.NoError(t, err)
				require.NotNil(t, signer)

				signature, err := signer.Sign(message, crand.Reader)
				require.NoError(t, err)

				err = schnorr.Verify(cipherSuite, publicKey, bytes.Join([][]byte{message, []byte("x")}, nil), signature)
				require.Error(t, err)
			})
		}
	}
}

func Test_InvalidMessageOrSignatureWithEd25519Verifier(t *testing.T) {
	t.Parallel()
	message := []byte("something")

	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.NewCurve(),
		Hash:  sha512.New,
	}
	publicKey, privateKey, err := schnorr.KeyGen(cipherSuite.Curve, crand.Reader)
	require.NoError(t, err)

	signer, err := schnorr.NewSigner(cipherSuite, privateKey)
	require.NoError(t, err)
	require.NotNil(t, signer)

	signature, err := signer.Sign(message, crand.Reader)
	require.NoError(t, err)

	nativeSignature := bytes.Join([][]byte{signature.R.ToAffineCompressed(), signature.S.Bytes()}, nil)
	ok := ed25519.Verify(publicKey.A.ToAffineCompressed(), []byte("something else"), nativeSignature)
	require.False(t, ok)
}
