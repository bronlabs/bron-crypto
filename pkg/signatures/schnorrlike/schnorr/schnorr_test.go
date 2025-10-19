package vanilla_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	vanilla "github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/schnorr"
)

func Test_VanillaSchnorr_BasicSigning_k256(t *testing.T) {
	t.Parallel()

	message := []byte("test message for vanilla schnorr")
	group := k256.NewCurve()
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, crand.Reader)
	require.NoError(t, err)

	// Generate key pair
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Sign message
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	// Verify signature
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature, pk, message)
	require.NoError(t, err)
}

func Test_VanillaSchnorr_BasicSigning_p256(t *testing.T) {
	t.Parallel()

	message := []byte("test message for vanilla schnorr on P256")
	group := p256.NewCurve()
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, crand.Reader)
	require.NoError(t, err)

	// Generate key pair
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Sign message
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	// Verify signature
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature, pk, message)
	require.NoError(t, err)
}

func Test_VanillaSchnorr_InvalidSignature(t *testing.T) {
	t.Parallel()

	message := []byte("original message")
	tampered := []byte("tampered message")
	group := k256.NewCurve()
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, crand.Reader)
	require.NoError(t, err)

	// Generate key pair
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Sign message
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	// Verify with tampered message should fail
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature, pk, tampered)
	require.Error(t, err)

	// Verify with original message should succeed
	err = verifier.Verify(signature, pk, message)
	require.NoError(t, err)
}

func Test_VanillaSchnorr_DifferentKeys(t *testing.T) {
	t.Parallel()

	message := []byte("test message")
	group := k256.NewCurve()
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, crand.Reader)
	require.NoError(t, err)

	// Generate first key pair
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk1, pk1, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Generate second key pair
	_, pk2, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Sign with first key
	signer, err := scheme.Signer(sk1)
	require.NoError(t, err)
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	// Verify with correct key should succeed
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature, pk1, message)
	require.NoError(t, err)

	// Verify with wrong key should fail
	err = verifier.Verify(signature, pk2, message)
	require.Error(t, err)
}

func Test_VanillaSchnorr_BatchVerify(t *testing.T) {
	t.Parallel()

	message1 := []byte("first message")
	message2 := []byte("second message")
	message3 := []byte("third message")

	group := k256.NewCurve()
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, crand.Reader)
	require.NoError(t, err)

	// Generate key pairs
	kg, err := scheme.Keygen()
	require.NoError(t, err)

	sk1, pk1, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	sk2, pk2, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	sk3, pk3, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Create signers
	signer1, err := scheme.Signer(sk1)
	require.NoError(t, err)

	signer2, err := scheme.Signer(sk2)
	require.NoError(t, err)

	signer3, err := scheme.Signer(sk3)
	require.NoError(t, err)

	// Sign messages
	sig1, err := signer1.Sign(message1)
	require.NoError(t, err)

	sig2, err := signer2.Sign(message2)
	require.NoError(t, err)

	sig3, err := signer3.Sign(message3)
	require.NoError(t, err)

	// Batch verify
	verifier, err := scheme.Verifier()
	require.NoError(t, err)

	err = verifier.BatchVerify(
		[]*vanilla.Signature[*k256.Point, *k256.Scalar]{sig1, sig2, sig3},
		[]*vanilla.PublicKey[*k256.Point, *k256.Scalar]{pk1, pk2, pk3},
		[][]byte{message1, message2, message3},
	)
	require.NoError(t, err)

	// Batch verify with wrong message should fail
	err = verifier.BatchVerify(
		[]*vanilla.Signature[*k256.Point, *k256.Scalar]{sig1, sig2, sig3},
		[]*vanilla.PublicKey[*k256.Point, *k256.Scalar]{pk1, pk2, pk3},
		[][]byte{message1, message1, message3}, // wrong message for sig2
	)
	require.Error(t, err)
}

func Test_VanillaSchnorr_EmptyMessage(t *testing.T) {
	t.Parallel()

	message := []byte{}
	group := k256.NewCurve()
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, crand.Reader)
	require.NoError(t, err)

	// Generate key pair
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Sign empty message
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	// Verify signature
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature, pk, message)
	require.NoError(t, err)
}

func Test_VanillaSchnorr_ResponseOperatorNegative(t *testing.T) {
	t.Parallel()

	message := []byte("test with negative response operator")
	group := k256.NewCurve()

	// Test with negative response operator (s = k - e*x)
	scheme, err := vanilla.NewScheme(group, sha256.New, true, true, nil, crand.Reader)
	require.NoError(t, err)

	// Generate key pair
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Sign message
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	// Verify signature
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature, pk, message)
	require.NoError(t, err)
}

func Test_VanillaSchnorr_SerializeSignature(t *testing.T) {
	t.Parallel()

	message := []byte("test serialization")
	group := k256.NewCurve()
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, crand.Reader)
	require.NoError(t, err)

	// Generate key pair
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk, _, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Sign message
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	// Get variant and serialize signature
	variant := scheme.Variant()

	serialized, err := variant.SerializeSignature(signature)
	require.NoError(t, err)
	require.NotNil(t, serialized)

	// The serialized signature should contain R followed by S
	// For k256, R is a compressed point (33 bytes) and S is a scalar (32 bytes)
	expectedLen := 33 + 32 // R + S
	require.Len(t, serialized, expectedLen)
}

func Test_VanillaSchnorr_VariantProperties(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, crand.Reader)
	require.NoError(t, err)

	variant := scheme.Variant()

	// Check variant type
	require.Equal(t, vanilla.VariantType, variant.Type())

	// Check that nonce is not a function of message (randomized)
	require.False(t, variant.NonceIsFunctionOfMessage())

	// Check hash function
	require.NotNil(t, variant.HashFunc())
}
