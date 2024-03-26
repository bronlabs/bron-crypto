// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/cipher"
	"slices"
	"strconv"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	keyedcipher "github.com/copperexchange/krypton-primitives/pkg/encryptions/cipher"
	"github.com/copperexchange/krypton-primitives/thirdparty/golang/go/src/crypto/internal/alias"
)

// The AES block size in bytes.
const BlockSize = 16

var _ keyedcipher.KeyedBlock = (*aesCipher)(nil) // CUSTOM

// A cipher is an instance of AES encryption using a particular key.
type aesCipher struct {
	enc []uint32
	dec []uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new [cipher.Block].
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16, 24, 32:
	}
	// CUSTOM: remove boring.NewCipher, we don't plan to use it here.
	return newCipher(key)
}

// newCipherGeneric creates and returns a new cipher.Block
// implemented in pure Go.
func newCipherGeneric(key []byte) (cipher.Block, error) {
	n := len(key) + 28
	c := aesCipher{make([]uint32, n), make([]uint32, n)}
	expandKeyGo(key, c.enc, c.dec)
	return &c, nil
}

func (*aesCipher) BlockSize() int { return BlockSize }

func (c *aesCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/aes: invalid buffer overlap")
	}
	encryptBlockGo(c.enc, dst, src)
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/aes: invalid buffer overlap")
	}
	decryptBlockGo(c.dec, dst, src)
}

// SetKey (CUSTOM) sets the key of the aesCipher.
func (c *aesCipher) SetKey(key []byte) error {
	if len(key) != len(c.enc)-28 {
		return KeySizeError(len(key))
	}
	expandKeyGo(key, c.enc, c.dec)
	return nil
}

// Clone (CUSTOM) creates a copy of the cipher.
func (c *aesCipher) Clone() keyedcipher.KeyedBlock {
	clonedCipher := &aesCipher{
		enc: slices.Clone(c.enc),
		dec: slices.Clone(c.dec),
	}
	return clonedCipher
}

// KeyedBlock is a cipher.Block that can be re-keyed without reallocation (CUSTOM).
func NewKeyedCipher(key []byte) (keyedcipher.KeyedBlock, error) {
	c, err := NewCipher(key)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create cipher")
	}
	keyedBlock, ok := c.(keyedcipher.KeyedBlock)
	if !ok {
		return nil, errs.NewFailed("cipher is not KeyedBlock")
	}
	return keyedBlock, nil
}
