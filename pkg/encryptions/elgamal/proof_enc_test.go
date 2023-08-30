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
	"github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
)

func TestEncryptionKeyEncryptAndProve(t *testing.T) {
	t.Parallel()

	curve := k256.New()
	domain := []byte("TestEncryptionKeyEncryptAndProve")

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
		cs, proof, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
			Domain:          domain,
			MessageIsHashed: true,
			GenProof:        true,
			ProofNonce:      domain,
		})
		require.NoError(t, err)

		err = ek.VerifyDomainEncryptProof(domain, cs, proof)
		require.NoError(t, err)

		_, dmsg, err := NewDecryptor(dk).VerifiableDecryptWithDomain(domain, cs)
		require.NoError(t, err)
		require.Equal(t, 0, msg.Cmp(dmsg))
	}
}

func TestEncryptionKeyEncryptAndProvePlaintextMsg(t *testing.T) {
	t.Parallel()

	curve := k256.New()
	domain := []byte("TestEncryptionKeyEncryptAndProve")

	ek, dk, err := NewKeys(curve, crand.Reader)
	require.NoError(t, err)

	msg := "testMessage"
	msgBytes := []byte(msg)

	cs, proof, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: false,
		GenProof:        true,
		ProofNonce:      domain,
	})
	require.NoError(t, err)

	err = ek.VerifyDomainEncryptProof(domain, cs, proof)
	require.NoError(t, err)

	dmsgBytes, _, err := NewDecryptor(dk).VerifiableDecryptWithDomain(domain, cs)
	require.NoError(t, err)
	require.Equal(t, msgBytes, dmsgBytes)
	require.Equal(t, msg, string(dmsgBytes))
}

func TestEncryptionKeyEncryptAndProveBlinding(t *testing.T) {
	t.Parallel()

	curve := k256.New()
	domain := []byte("TestEncryptionKeyEncryptAndProveBlinding")

	ek, dk, err := NewKeys(curve, crand.Reader)
	require.NoError(t, err)

	testMsgs := []*struct {
		test, blinding curves.Scalar
	}{
		{curve.Scalar().New(0), curve.Scalar().New(1)},
		{curve.Scalar().New(10), curve.Scalar().New(2)},
		{curve.Scalar().New(20), curve.Scalar().New(3)},
		{curve.Scalar().New(30), curve.Scalar().New(4)},
		{curve.Scalar().New(40), curve.Scalar().New(5)},
		{curve.Scalar().New(50), curve.Scalar().New(6)},
		{curve.Scalar().New(100), curve.Scalar().New(7)},
		{curve.Scalar().New(1000), curve.Scalar().New(8)},
		{curve.Scalar().New(10000), curve.Scalar().New(9)},
		{curve.Scalar().New(100000), curve.Scalar().New(10)},
		{curve.Scalar().New(1000000), curve.Scalar().New(11)},
	}
	for _, msg := range testMsgs {
		msgTestBytes := msg.test.Bytes()
		cs, proof, err := ek.VerifiableEncrypt(msgTestBytes, &EncryptParams{
			Domain:          domain,
			MessageIsHashed: true,
			Blinding:        msg.blinding,
			GenProof:        true,
			ProofNonce:      domain,
		})
		require.NoError(t, err)

		err = ek.VerifyDomainEncryptProof(domain, cs, proof)
		require.NoError(t, err)

		_, dmsg, err := NewDecryptor(dk).VerifiableDecryptWithDomain(domain, cs)
		require.NoError(t, err)
		require.Equal(t, 0, msg.test.Cmp(dmsg))
	}
}

func TestEncryptionKeyEncryptAndProveInvalidInputs(t *testing.T) {
	t.Parallel()

	curve := bls12381.NewG1()
	domain := []byte("TestEncryptionKeyEncryptAndProveInvalidInputs")

	ek, _, err := NewKeys(curve, crand.Reader)
	require.NoError(t, err)

	_, _, err = ek.VerifiableEncrypt(nil, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: true,
		GenProof:        true,
		ProofNonce:      domain,
	})
	require.Error(t, err)

	msg2 := curve.Scalar().New(2)
	msg2Bytes := msg2.Bytes()
	_, _, err = ek.VerifiableEncrypt(msg2Bytes, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: true,
		Blinding:        curve.Scalar().New(0),
		GenProof:        true,
		ProofNonce:      domain,
	})
	require.Error(t, err)
}
