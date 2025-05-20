package trsa_test

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

func Test_PSSHappyPath(t *testing.T) {
	t.Parallel()
	const saltSize = 32
	hashFunc := sha256.New
	prng := crand.Reader

	rsaKey, err := rsa.GenerateKey(prng, trsa.RsaBitLen)
	require.NoError(t, err)
	message := []byte("hello world")
	digest, err := hashing.Hash(hashFunc, message)
	require.NoError(t, err)
	salt := make([]byte, saltSize)
	_, err = io.ReadFull(prng, salt)
	require.NoError(t, err)

	baseBytes, err := trsa.EmsaPSSEncode(digest, rsaKey.N.BitLen()-1, salt, hashFunc())
	require.NoError(t, err)
	base := new(big.Int).SetBytes(baseBytes)
	signature := new(big.Int).Exp(base, rsaKey.D, rsaKey.N)
	signatureBytes := make([]byte, (trsa.RsaBitLen+7)/8)
	signature.FillBytes(signatureBytes)

	err = rsa.VerifyPSS(&rsaKey.PublicKey, crypto.SHA256, digest, signatureBytes, &rsa.PSSOptions{SaltLength: saltSize})
	require.NoError(t, err)
}
