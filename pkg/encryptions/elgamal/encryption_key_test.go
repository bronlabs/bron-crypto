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

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
)

func TestEncryptionKeyEncrypt(t *testing.T) {
	t.Parallel()

	curve := k256.New()
	domain := []byte("TestEncryptionKeyEncrypt")

	ek, dk, err := NewKeys(curve, crand.Reader)
	require.NoError(t, err)

	testMsgs := []curves.Scalar{
		curve.Scalar().New(0),
		curve.Scalar().New(10),
		curve.Scalar().New(20),
		curve.Scalar().New(30),
		curve.Scalar().New(40),
		curve.Scalar().New(50),
		curve.Scalar().New(100),
		curve.Scalar().New(1000),
		curve.Scalar().New(10000),
		curve.Scalar().New(100000),
		curve.Scalar().New(1000000),
	}

	for _, msg := range testMsgs {
		msgBytes := msg.Bytes()
		require.NoError(t, err)
		cs, _, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
			Domain:          domain,
			MessageIsHashed: true,
		})
		require.NoError(t, err)
		_, m, err := NewDecryptor(dk).VerifiableDecryptWithDomain(domain, cs)
		require.NoError(t, err)
		require.Equal(t, m.Cmp(msg), 0)
	}
}

func TestEncryptionKeyEncryptInvalidMessages(t *testing.T) {
	t.Parallel()

	curve := k256.New()
	domain := []byte("TestEncryptionKeyEncryptInvalidMessages")

	ek, dk, err := NewKeys(curve, crand.Reader)
	require.NoError(t, err)

	// nil message
	_, _, err = ek.VerifiableEncrypt(nil, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: true,
	})
	require.Error(t, err)

	msg := curve.Scalar().New(1234567890)
	msgBytes := msg.Bytes()
	cs, _, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: true,
	})
	require.NoError(t, err)
	// invalid domain i.e. not the same domain used to encrypt
	_, _, err = NewDecryptor(dk).VerifiableDecryptWithDomain([]byte{}, cs)
	require.Error(t, err)
}
