package cipher_test

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/thirdparty/golang/go/src/crypto/aes"
)

func Test_keyedblock(t *testing.T) {
	t.Parallel()
	var err error
	numRuns := 100
	input, output, ctxt, ctxt2, key := new([16]byte), new([16]byte), new([16]byte), new([16]byte), new([16]byte)
	for i := 0; i < numRuns; i++ {
		_, err = crand.Read(input[:])
		require.NoError(t, err)
		_, err = crand.Read(key[:])
		require.NoError(t, err)
		// First encryption & decryption
		c, err := aes.NewKeyedCipher(key[:])
		require.NoError(t, err)
		c.Encrypt(ctxt[:], input[:])
		c.Decrypt(output[:], ctxt[:])
		require.True(t, bytes.Equal(input[:], output[:]))
		// Second encryption & decryption, after setting the key to something else
		c.SetKey(output[:])           // Noise
		c.Encrypt(ctxt2[:], input[:]) // Noise
		c.SetKey(key[:])
		c.Encrypt(ctxt2[:], input[:])
		c.Decrypt(output[:], ctxt2[:])
		require.True(t, bytes.Equal(input[:], output[:]))
		require.True(t, bytes.Equal(ctxt[:], ctxt2[:]))
		// Third encryption & decryption, after cloning
		c2 := c.Clone()
		c2.Encrypt(ctxt[:], input[:]) // Noise
		c2.SetKey(key[:])
		c2.Encrypt(ctxt[:], input[:])
		c2.Decrypt(output[:], ctxt[:])
		require.True(t, bytes.Equal(input[:], output[:]))
		require.True(t, bytes.Equal(ctxt[:], ctxt2[:]))
	}
}

func BenchmarkKeyedAes(b *testing.B) {
	input, ctxt, key := make([]byte, 16), make([]byte, 16), make([]byte, 16)
	b.ResetTimer()
	b.Run("SetKey->Encrypt", func(b *testing.B) {
		for range b.N {
			// Generate random input and key
			b.StopTimer()
			_, err := crand.Read(input)
			require.NoError(b, err)
			_, err = crand.Read(key)
			require.NoError(b, err)
			cipher, err := aes.NewKeyedCipher(key)
			require.NoError(b, err)
			// SetKey->Encrypt
			b.StartTimer()
			err = cipher.SetKey(key)
			require.NoError(b, err)
			cipher.Encrypt(ctxt, input)
		}
	})
	b.Run("NewCipher->Encrypt", func(b *testing.B) {
		for range b.N {
			// Generate random input and key
			b.StopTimer()
			_, err := crand.Read(input)
			require.NoError(b, err)
			_, err = crand.Read(key)
			require.NoError(b, err)
			// NewCipher->Encrypt
			b.StartTimer()
			cipherBlock, err := aes.NewCipher(key)
			require.NoError(b, err)
			cipherBlock.Encrypt(ctxt, input)
		}
	})
}
