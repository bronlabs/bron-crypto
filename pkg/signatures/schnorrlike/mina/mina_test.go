package mina

// import (
// 	"crypto/rand"
// 	"testing"

// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// )

// func TestEncodeDecodeRoundTrip(t *testing.T) {
// 	// Generate a new key pair
// 	scheme, err := NewRandomisedScheme(TestNet, rand.Reader)
// 	require.NoError(t, err)

// 	kg, err := scheme.Keygen()
// 	require.NoError(t, err)

// 	privateKey, publicKey, err := kg.Generate(rand.Reader)
// 	require.NoError(t, err)

// 	// Encode private key
// 	encodedPriv, err := EncodePrivateKey(privateKey)
// 	require.NoError(t, err)
// 	t.Logf("Generated private key: %s", encodedPriv)

// 	// Decode it back
// 	decodedPriv, err := DecodePrivateKey(encodedPriv)
// 	require.NoError(t, err)

// 	// Verify they match
// 	assert.Equal(t, privateKey.Value().Bytes(), decodedPriv.Value().Bytes())

// 	// Do the same for public key
// 	encodedPub, err := EncodePublicKey(publicKey)
// 	require.NoError(t, err)
// 	t.Logf("Generated public key: %s", encodedPub)

// 	decodedPub, err := DecodePublicKey(encodedPub)
// 	require.NoError(t, err)

// 	assert.Equal(t, publicKey.Value().Bytes(), decodedPub.Value().Bytes())
// }
