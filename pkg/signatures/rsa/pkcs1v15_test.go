package rsa_test

import (
	"crypto"
	crand "crypto/rand"
	nativeRsa "crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/signatures/rsa"
)

func Test_PadPKCS1v15(t *testing.T) {
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
	d := new(saferith.Nat).SetBig(key.D, bitLen)
	n := new(saferith.Nat).SetBig(key.N, bitLen)

	padding := rsa.NewPKCS1v15Padding()
	paddedDigestNat, err := padding.HashAndPad(bitLen, hashFunc, message)
	require.NoError(t, err)

	signature := new(saferith.Nat).Exp(paddedDigestNat, d, saferith.ModulusFromNat(n))
	signatureBytes := signature.Bytes()

	err = nativeRsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest, signatureBytes)
	require.NoError(t, err)
}
