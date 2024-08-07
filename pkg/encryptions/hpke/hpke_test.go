package hpke_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/hpke"
)

func Test_AuthSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	senderSk, err := p256.NewCurve().ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	senderPk := p256.NewCurve().ScalarBaseMult(senderSk)

	receiverSk, err := p256.NewCurve().ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	receiverPk := p256.NewCurve().ScalarBaseMult(receiverSk)

	suite := &hpke.CipherSuite{
		KDF:  hpke.KDF_HKDF_SHA256,
		KEM:  hpke.DHKEM_P256_HKDF_SHA256,
		AEAD: hpke.AEAD_CHACHA_20_POLY_1305,
	}

	plainText := []byte("Hello")
	cipherText, epk, err := hpke.Seal(hpke.Auth, suite, plainText, []byte("aad"), receiverPk, &hpke.PrivateKey{D: senderSk, PublicKey: senderPk}, nil, nil, nil, crand.Reader)
	require.NoError(t, err)

	decrypted, err := hpke.Open(hpke.Auth, suite, cipherText, []byte("aad"), &hpke.PrivateKey{D: receiverSk, PublicKey: receiverPk}, epk, senderPk, nil, nil, nil)
	require.NoError(t, err)

	require.Equal(t, plainText, decrypted)
}
