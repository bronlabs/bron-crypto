package mina_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()
	// Generate a new key pair
	scheme, err := mina.NewRandomisedScheme(mina.TestNet, pcg.NewRandomised())
	require.NoError(t, err)

	kg, err := scheme.Keygen()
	require.NoError(t, err)

	privateKey, publicKey, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)

	// Encode private key
	encodedPriv, err := mina.EncodePrivateKey(privateKey)
	require.NoError(t, err)
	t.Logf("Generated private key: %s", encodedPriv)

	// Decode it back
	decodedPriv, err := mina.DecodePrivateKey(encodedPriv)
	require.NoError(t, err)

	// Verify they match
	assert.Equal(t, privateKey.Value().Bytes(), decodedPriv.Value().Bytes())

	// Do the same for public key
	encodedPub, err := mina.EncodePublicKey(publicKey)
	require.NoError(t, err)
	t.Logf("Generated public key: %s", encodedPub)

	decodedPub, err := mina.DecodePublicKey(encodedPub)
	require.NoError(t, err)

	assert.Equal(t, publicKey.Value().Bytes(), decodedPub.Value().Bytes())
}

// TestSchnorrSignatureLogic verifies the Schnorr signature algorithm is correct
// Schnorr signature (Mina variant):
// 1. Generate nonce k, compute R = k*G
// 2. Ensure R has even y-coordinate (negate k if needed)
// 3. Compute challenge e = Hash(R.x, PK, message)
// 4. Compute response s = k + e*sk
// 5. Signature is (R.x, s)
// 6. Verification: s*G == R + e*PK
func TestSchnorrSignatureLogic(t *testing.T) {
	t.Parallel()
	// Create a random scheme
	scheme, err := mina.NewRandomisedScheme(mina.TestNet, pcg.NewRandomised())
	require.NoError(t, err)

	// Generate a key pair
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	privateKey, publicKey, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)

	// Create a simple message
	msg := new(mina.ROInput).Init()
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
	left := pasta.NewPallasCurve().ScalarBaseMul(sig.S)

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
	t.Parallel()
	// Decode test private key
	privateKey, err := mina.DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)

	// Create deterministic scheme
	scheme, err := mina.NewScheme(mina.TestNet, privateKey)
	require.NoError(t, err)

	// Create two signers
	signer1, err := scheme.Signer(privateKey)
	require.NoError(t, err)

	signer2, err := scheme.Signer(privateKey)
	require.NoError(t, err)

	// Sign the same message twice
	msg := new(mina.ROInput).Init()
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
	t.Parallel()
	// Create multiple random schemes and verify R parity
	for range 10 {
		scheme, err := mina.NewRandomisedScheme(mina.TestNet, pcg.NewRandomised())
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		privateKey, publicKey, err := kg.Generate(pcg.NewRandomised())
		require.NoError(t, err)

		signer, err := scheme.Signer(privateKey)
		require.NoError(t, err)

		msg := new(mina.ROInput).Init()
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
