//go:build !amd64 && !arm64 && !ppc64 && !ppc64le

package keyedblock

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type AesCipherGo struct {
	aesC cipher.Block
	key  []byte
}

// NewCipher creates and returns a new cipher.Block. The key argument should be
// the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func NewKeyedCipher(key []byte) (aesCipherGo KeyedBlock, err error) {
	aesC, err := aes.NewCipher(key)
	if err != nil {
		return nil, errs.WrapFailed(err, "Could not create new aes cipher")
	}
	aesCipherGo = &AesCipherGo{
		aesC: aesC,
	}
	return aesCipherGo, nil
}

// Clone creates a copy of the KeyedBlock.
func (c *AesCipherGo) Clone(key []byte) KeyedBlock {
	aesC, err := aes.NewCipher(key)
	if err != nil {
		panic("Could not clone aes cipher")
	}
	return &AesCipherGo{
		aesC: aesC,
	}
}

func (c *AesCipherGo) BlockSize() int {
	return c.aesC.BlockSize()
}

func (c *AesCipherGo) Encrypt(dst, src []byte) {
	c.aesC.Encrypt(dst, src)
}

func (c *AesCipherGo) Decrypt(dst, src []byte) {
	c.aesC.Decrypt(dst, src)
}

// SetKey sets the key of the aesCipher.
func (c *AesCipherGo) SetKey(key []byte) {
	aesC, err := aes.NewCipher(key)
	if err != nil {
		panic("Could set aes with new key")
	}
	c.aesC = aesC
}
