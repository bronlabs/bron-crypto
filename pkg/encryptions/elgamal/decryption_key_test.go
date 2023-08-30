//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package elgamal

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
)

func TestDecryptionKeyDecryptBadCiphertext(t *testing.T) {
	t.Parallel()

	curve := k256.New()
	_, dk, err := NewKeys(curve, crand.Reader)
	require.NoError(t, err)

	// nil ciphertext
	_, _, err = NewDecryptor(dk).VerifiableDecryptWithDomain([]byte{}, nil)
	require.Error(t, err)

	// empty ciphertext
	_, _, err = NewDecryptor(dk).VerifiableDecryptWithDomain([]byte{}, new(CipherText))
	require.Error(t, err)

	cs := new(CipherText)
	cs.C1 = curve.Point().Generator()
	cs.C2 = curve.Point().Generator()
	cs.Nonce = make([]byte, 12)
	cs.Aead = make([]byte, 16)

	// empty data in ciphertext
	_, _, err = NewDecryptor(dk).VerifiableDecryptWithDomain([]byte{}, cs)
	require.Error(t, err)

	cs.C1 = curve.Point().Identity()
	cs.C2 = curve.Point().Identity()
	cs.Nonce = []byte{}
	cs.Aead = []byte{}
	// ensure no panic happens when nonce and aead are invalid lengths
	_, _, err = NewDecryptor(dk).VerifiableDecryptWithDomain([]byte{}, cs)
	require.Error(t, err)
}
