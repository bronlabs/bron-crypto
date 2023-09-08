// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//go:build amd64 || arm64 || ppc64 || ppc64le

package keyedblock

import (
	"github.com/copperexchange/krypton/pkg/base/errs"
)

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func decryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc, dec *uint32)

// The AES block size in bytes.
const BlockSize = 16

type AesCipherAsm struct {
	enc    []uint32
	dec    []uint32
	rounds int
}

// NewCipher creates and returns a new cipher.Block. The key argument should be
// the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func NewKeyedCipher(key []byte) (KeyedBlock, error) {
	// if !supportsAES {
	// 	return nil, errs.NewFailed("AES hardware acceleration not supported")
	// }
	n := len(key) + 28
	c := AesCipherAsm{
		enc: make([]uint32, n),
		dec: make([]uint32, n),
	}
	switch len(key) {
	case 16:
		c.rounds = 10
	case 24:
		c.rounds = 12
	case 32:
		c.rounds = 14
	default:
		return nil, errs.NewInvalidArgument("Aes Key has wrong size")
	}

	expandKeyAsm(c.rounds, &key[0], &c.enc[0], &c.dec[0])
	return &c, nil
}

// Clone creates a copy of the struct. Key is unused (required only by the Go imlementation).
func (c *AesCipherAsm) Clone(key []byte) KeyedBlock {
	return &AesCipherAsm{
		enc:    append([]uint32(nil), c.enc...),
		dec:    append([]uint32(nil), c.dec...),
		rounds: c.rounds,
	}
}

func (*AesCipherAsm) BlockSize() int {
	return BlockSize
}

// Encrypt encrypts the first block in src into dst. Dst and src must overlap
// entirely or not at all (Warning! not checked).
func (c *AesCipherAsm) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	encryptBlockAsm(len(c.enc)/4-1, &c.enc[0], &dst[0], &src[0])
}

// Decrypt decrypts the first block in src into dst. Dst and src must overlap
// entirely or not at all (Warning! not checked).
func (c *AesCipherAsm) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	decryptBlockAsm(len(c.dec)/4-1, &c.dec[0], &dst[0], &src[0])
}

// SetKey sets the key of the aesCipher. Warning! key size not checked.
func (c *AesCipherAsm) SetKey(key []byte) {
	expandKeyAsm(c.rounds, &key[0], &c.enc[0], &c.dec[0])
}
