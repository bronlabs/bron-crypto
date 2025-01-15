// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64 || ppc64 || ppc64le) && !purego

package aes

import (
	"crypto/cipher"
	"slices"

	kcipher "github.com/bronlabs/krypton-primitives/pkg/encryptions/cipher"
	"github.com/bronlabs/krypton-primitives/thirdparty/golang/go/src/crypto/internal/alias"
)

// defined in asm_*.s.

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func decryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc, dec *uint32)

var _ kcipher.KeyedBlock = (*aesCipherAsm)(nil) // CUSTOM

type aesCipherAsm struct {
	aesCipher
}

// aesCipherGCM implements crypto/cipher.gcmAble so that crypto/cipher.NewGCM
// will use the optimised implementation in aes_gcm.go when possible.
// Instances of this type only exist when hasGCMAsm returns true. Likewise,
// the gcmAble implementation is in aes_gcm.go.
type aesCipherGCM struct {
	aesCipherAsm
}

// CUSTOM: hardcode supportsAES = true. We avoid checking for AES hardware
// acceleration because it is only available in internal/cpu package (note:
// golang.org/x/sys/cpu package doesn't initialise properly, hence we cannot use
// it here). Hardcode GFMUL=false since we don't use GCM.
var supportsAES = true
var supportsGFMUL = false // cpu.X86.HasPCLMULQDQ || cpu.ARM64.HasPMULL

func newCipher(key []byte) (cipher.Block, error) {
	if !supportsAES {
		return newCipherGeneric(key)
	}
	n := len(key) + 28
	c := aesCipherAsm{aesCipher{make([]uint32, n), make([]uint32, n)}}
	var rounds int
	switch len(key) {
	case 128 / 8:
		rounds = 10
	case 192 / 8:
		rounds = 12
	case 256 / 8:
		rounds = 14
	default:
		return nil, KeySizeError(len(key))
	}

	expandKeyAsm(rounds, &key[0], &c.enc[0], &c.dec[0])
	if supportsAES && supportsGFMUL {
		return &aesCipherGCM{c}, nil
	}
	return &c, nil
}

func (*aesCipherAsm) BlockSize() int { return BlockSize }

func (c *aesCipherAsm) Encrypt(dst, src []byte) {
	// CUSTOM: remove boring.Unreachable()
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/aes: invalid buffer overlap")
	}
	encryptBlockAsm(len(c.enc)/4-1, &c.enc[0], &dst[0], &src[0])
}

func (c *aesCipherAsm) Decrypt(dst, src []byte) {
	// CUSTOM: remove boring.Unreachable()
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/aes: invalid buffer overlap")
	}
	decryptBlockAsm(len(c.dec)/4-1, &c.dec[0], &dst[0], &src[0])
}

// expandKey is used by BenchmarkExpand to ensure that the asm implementation
// of key expansion is used for the benchmark when it is available.
func expandKey(key []byte, enc, dec []uint32) {
	if supportsAES {
		rounds := 10 // rounds needed for AES128
		switch len(key) {
		case 192 / 8:
			rounds = 12
		case 256 / 8:
			rounds = 14
		}
		expandKeyAsm(rounds, &key[0], &enc[0], &dec[0])
	} else {
		expandKeyGo(key, enc, dec)
	}
}

// SetKey (CUSTOM) sets the key of the aesCipher.
func (c *aesCipherAsm) SetKey(key []byte) error {
	if len(key) != len(c.enc)-28 {
		return KeySizeError(len(key))
	}
	expandKey(key, c.enc, c.dec)
	return nil
}

// Clone (CUSTOM) creates a copy of the cipher.
func (c *aesCipherAsm) Clone() kcipher.KeyedBlock {
	clonedCipher := &aesCipherAsm{
		aesCipher: aesCipher{
			enc: slices.Clone(c.enc),
			dec: slices.Clone(c.dec),
		},
	}
	return clonedCipher
}
