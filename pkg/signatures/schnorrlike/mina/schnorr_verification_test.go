package mina

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSchnorrSignatureLogic verifies the Schnorr signature algorithm is correct
// Schnorr signature (Mina variant):
// 1. Generate nonce k, compute R = k*G
// 2. Ensure R has even y-coordinate (negate k if needed)
// 3. Compute challenge e = Hash(R.x, PK, message)
// 4. Compute response s = k + e*sk
// 5. Signature is (R.x, s)
// 6. Verification: s*G == R + e*PK
func TestSchnorrSignatureLogic(t *testing.T) {
	// Create a random scheme
	scheme, err := NewRandomisedScheme(TestNet, rand.Reader)
	require.NoError(t, err)

	// Generate a key pair
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	privateKey, publicKey, err := kg.Generate(rand.Reader)
	require.NoError(t, err)

	// Create a simple message
	msg := new(ROInput).Init()
	msg.AddString("test message for schnorr verification")

	// Create signer
	signer, err := scheme.Signer(privateKey)
	require.NoError(t, err)

	// Sign the message
	sig, err := signer.Sign(msg)
	require.NoError(t, err)

	t.Logf("Generated signature with R.x and S")

	// Verify the signature manually to check algorithm correctness
	// Get the challenge e
	e, err := signer.Variant().ComputeChallenge(sig.R, publicKey.V, msg)
	require.NoError(t, err)
	t.Logf("Challenge e computed")

	// Verify: s*G == R + e*PK
	// Left side: s*G
	left := group.ScalarBaseMul(sig.S)

	// Right side: R + e*PK
	ePK := publicKey.V.ScalarMul(e)
	right := sig.R.Op(ePK)

	t.Logf("Verification equation: s*G == R + e*PK")
	require.True(t, left.Equal(right), "Schnorr verification equation failed")

	// Also verify using the verifier
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(sig, publicKey, msg)
	require.NoError(t, err, "Verifier should accept valid signature")

	t.Log("✓ Schnorr signature algorithm is correct")
}

// TestSchnorrDeterministicNonce verifies deterministic nonce generation
func TestSchnorrDeterministicNonce(t *testing.T) {
	// Decode test private key
	privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)

	// Create deterministic scheme
	scheme, err := NewScheme(TestNet, privateKey)
	require.NoError(t, err)

	// Create two signers
	signer1, err := scheme.Signer(privateKey)
	require.NoError(t, err)

	signer2, err := scheme.Signer(privateKey)
	require.NoError(t, err)

	// Sign the same message twice
	msg := new(ROInput).Init()
	msg.AddString("same message")

	sig1, err := signer1.Sign(msg)
	require.NoError(t, err)

	sig2, err := signer2.Sign(msg)
	require.NoError(t, err)

	// Signatures should be identical (deterministic)
	rx1, _ := sig1.R.AffineX()
	rx2, _ := sig2.R.AffineX()
	require.True(t, rx1.Equal(rx2), "R.x should be the same for deterministic nonces")
	require.True(t, sig1.S.Equal(sig2.S), "S should be the same for deterministic nonces")

	t.Log("✓ Deterministic nonce generation is consistent")
}

// TestSchnorrParityCorrection verifies R has even y-coordinate
func TestSchnorrParityCorrection(t *testing.T) {
	// Create multiple random schemes and verify R parity
	for i := 0; i < 10; i++ {
		scheme, err := NewRandomisedScheme(TestNet, rand.Reader)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		privateKey, publicKey, err := kg.Generate(rand.Reader)
		require.NoError(t, err)

		signer, err := scheme.Signer(privateKey)
		require.NoError(t, err)

		msg := new(ROInput).Init()
		msg.AddString("parity test")

		sig, err := signer.Sign(msg)
		require.NoError(t, err)

		// Check that R has even y-coordinate
		ry, err := sig.R.AffineY()
		require.NoError(t, err)
		require.False(t, ry.IsOdd(), "R.y should be even (parity correction should ensure this)")

		// Verify signature
		verifier, err := scheme.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(sig, publicKey, msg)
		require.NoError(t, err)
	}

	t.Log("✓ All signatures have R with even y-coordinate")
}
