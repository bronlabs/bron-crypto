package keyedblock_test

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/hashing/tmmohash/keyedblock"
)

func Test_keyedblock(t *testing.T) {
	var err error
	numRuns := 100
	input, output, ctxt, ctxt2, key := new([16]byte), new([16]byte), new([16]byte), new([16]byte), new([16]byte)
	for i := 0; i < numRuns; i++ {
		_, err = crand.Read(input[:])
		require.NoError(t, err)
		_, err = crand.Read(key[:])
		require.NoError(t, err)
		// First encryptuin & decryption
		c, err := keyedblock.NewKeyedCipher(key[:])
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
		c2 := c.Clone(key[:])
		c2.Encrypt(ctxt[:], input[:]) // Noise
		c2.SetKey(key[:])
		c2.Encrypt(ctxt[:], input[:])
		c2.Decrypt(output[:], ctxt[:])
		require.True(t, bytes.Equal(input[:], output[:]))
		require.True(t, bytes.Equal(ctxt[:], ctxt2[:]))
	}
}
