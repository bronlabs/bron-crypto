package rsa_test

import (
	"crypto"
	crand "crypto/rand"
	nativeRsa "crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/signatures/rsa"
)

func Test_PadPKCS1v15(t *testing.T) {
	t.Parallel()

	const bitLen = 1024
	prng := crand.Reader
	message := []byte("Hello")
	hashFunc := sha256.New
	hasher := hashFunc()
	hasher.Write(message)
	digest := hasher.Sum(nil)

	key, err := nativeRsa.GenerateKey(prng, bitLen)
	require.NotNil(t, key)
	require.NoError(t, err)

	padding := rsa.NewPKCS1v15Padding()
	paddedDigest, err := padding.HashAndPad(bitLen, hashFunc, message)
	require.NoError(t, err)

	signature := new(big.Int).Exp(paddedDigest, key.D, key.N)
	signatureBytes := signature.Bytes()

	err = nativeRsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest, signatureBytes)
	require.NoError(t, err)
}
