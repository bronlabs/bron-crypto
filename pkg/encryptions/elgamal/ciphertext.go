//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package elgamal

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

// CipherText represents verifiably encrypted ciphertext
// using El-Gamal encryption.
type CipherText struct {
	C1, C2      curves.Point
	Nonce       []byte
	Aead        []byte
	MsgIsHashed bool
}

// HomomorphicCipherText represents encrypted ciphertexts
// that have been added together. The result when decrypted
// does not include the AEAD encrypted ciphertexts since
// these are not homomorphic. This is solely for checking
// results or ignoring the AEAD ciphertext.
type HomomorphicCipherText struct {
	C1, C2 curves.Point
}

// ToHomomorphicCipherText returns the El-Gamal points that can be
// homomorphically multiplied
func (c *CipherText) ToHomomorphicCipherText() *HomomorphicCipherText {
	return &HomomorphicCipherText{
		C1: c.C1,
		C2: c.C2,
	}
}

// Add combines two ciphertexts multiplicatively homomorphic.
func (c *HomomorphicCipherText) Add(rhs *HomomorphicCipherText) *HomomorphicCipherText {
	return &HomomorphicCipherText{
		C1: c.C1.Add(rhs.C1),
		C2: c.C2.Add(rhs.C2),
	}
}

// Decrypt returns the C2 - C1.
func (c *HomomorphicCipherText) Decrypt(dk *DecryptionKey) (curves.Point, error) {
	if dk == nil {
		return nil, errs.NewIsNil("key is nil")
	}
	return c.C2.Sub(c.C1.Mul(dk.x)), nil
}
