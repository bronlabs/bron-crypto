package mina_test

import (
	"encoding/hex"
	"math/big"
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

// TestModernSchnorrSignatureLogic verifies the modern Schnorr signature algorithm is correct.
// Modern Schnorr signature (Mina variant):
// 1. Generate a random nonce k, compute R = k*G
// 2. Ensure R has even y-coordinate (negate k if needed)
// 3. Compute challenge e with modern chunked packing and Kimchi Poseidon
// 4. Compute response s = k + e*sk
// 5. Verification: s*G == R + e*PK
func TestModernSchnorrSignatureLogic(t *testing.T) {
	t.Parallel()
	// Create a modern randomised scheme
	scheme, err := mina.NewModernRandomisedScheme(mina.TestNet, pcg.NewRandomised())
	require.NoError(t, err)

	// Generate a key pair
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	privateKey, publicKey, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)

	// Create a simple message
	msg := new(mina.ROInput).Init()
	msg.AddString("test message for modern schnorr verification")

	// Create signer
	signer, err := scheme.Signer(privateKey)
	require.NoError(t, err)

	// Sign the message
	sig, err := signer.Sign(msg)
	require.NoError(t, err)

	t.Logf("Generated modern signature with R.x and S")

	// Verify the signature manually to check algorithm correctness
	// Get the challenge e
	e, err := signer.Variant().ComputeChallenge(sig.R, publicKey.V, msg)
	require.NoError(t, err)
	t.Logf("Modern challenge e computed")

	// Verify: s*G == R + e*PK
	// Left side: s*G
	left := pasta.NewPallasCurve().ScalarBaseMul(sig.S)

	// Right side: R + e*PK
	ePK := publicKey.V.ScalarMul(e)
	right := sig.R.Op(ePK)

	t.Logf("Verification equation: s*G == R + e*PK")
	require.True(t, left.Equal(right), "modern Schnorr verification equation failed")

	// Also verify using the modern verifier
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(sig, publicKey, msg)
	require.NoError(t, err, "Modern verifier should accept valid signature")

	t.Log("✓ Modern Schnorr signature algorithm is correct")
}

// TestModernSchnorrDeterministicNonce verifies modern deterministic nonce generation.
func TestModernSchnorrDeterministicNonce(t *testing.T) {
	t.Parallel()
	// Decode test private key
	privateKey, err := mina.DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)

	// Create modern deterministic scheme
	scheme, err := mina.NewModernScheme(mina.TestNet, privateKey)
	require.NoError(t, err)

	// Create two signers
	signer1, err := scheme.Signer(privateKey)
	require.NoError(t, err)

	signer2, err := scheme.Signer(privateKey)
	require.NoError(t, err)

	// Sign the same message twice
	msg := new(mina.ROInput).Init()
	msg.AddString("same modern message")

	sig1, err := signer1.Sign(msg)
	require.NoError(t, err)

	sig2, err := signer2.Sign(msg)
	require.NoError(t, err)

	// Signatures should be identical (deterministic)
	rx1, _ := sig1.R.AffineX()
	rx2, _ := sig2.R.AffineX()
	require.True(t, rx1.Equal(rx2), "R.x should be the same for modern deterministic nonces")
	require.True(t, sig1.S.Equal(sig2.S), "S should be the same for modern deterministic nonces")

	t.Log("✓ Modern deterministic nonce generation is consistent")
}

// TestModernSchnorrParityCorrection verifies modern signatures have an even R y-coordinate.
func TestModernSchnorrParityCorrection(t *testing.T) {
	t.Parallel()
	// Create multiple modern randomised schemes and verify R parity
	for range 10 {
		scheme, err := mina.NewModernRandomisedScheme(mina.TestNet, pcg.NewRandomised())
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		privateKey, publicKey, err := kg.Generate(pcg.NewRandomised())
		require.NoError(t, err)

		signer, err := scheme.Signer(privateKey)
		require.NoError(t, err)

		msg := new(mina.ROInput).Init()
		msg.AddString("modern parity test")

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

	t.Log("✓ All modern signatures have R with even y-coordinate")
}

// TestModernSignatureO1jsVector verifies byte-exact compatibility with o1js modern sign.
func TestModernSignatureO1jsVector(t *testing.T) {
	t.Parallel()
	// Create the private key and field message used by the o1js vector
	privateKey, err := mina.NewPrivateKey(pasta.NewPallasScalarField().FromUint64(1))
	require.NoError(t, err)
	msg := new(mina.ROInput).Init()
	msg.AddFields(pasta.NewPallasBaseField().FromUint64(42))

	// Sign with the modern deterministic scheme
	scheme, err := mina.NewModernScheme(mina.TestNet, privateKey)
	require.NoError(t, err)
	signer, err := scheme.Signer(privateKey)
	require.NoError(t, err)
	sig, err := signer.Sign(msg)
	require.NoError(t, err)
	serialized, err := mina.SerializeSignature(sig)
	require.NoError(t, err)

	// The serialized signature must match o1js signFieldElement byte-for-byte
	const expected = "2c7344f8ef01bfabb9c7c5cebe90d22beca036ff677400185c44f380d3e032170c9050c1990344dfaecc418e9ea6a3fcd5a95deabbadb1d25e3fcba5f37dc826"
	require.Equal(t, expected, hex.EncodeToString(serialized))

	t.Log("✓ Modern signature matches the o1js field-element vector")
}

// TestModernSignatureO1jsPackedInputVector verifies modern chunked input packing against o1js.
func TestModernSignatureO1jsPackedInputVector(t *testing.T) {
	t.Parallel()
	// Create the private key and mixed field/packed message used by the o1js vector
	privateKey, err := mina.NewPrivateKey(pasta.NewPallasScalarField().FromUint64(1))
	require.NoError(t, err)
	msg := new(mina.ROInput).Init()
	msg.AddFields(pasta.NewPallasBaseField().FromUint64(42))
	// Equivalent to o1js packed input [[5n, 3], [2n, 2]]
	msg.AddBits(true, false, true, true, false)

	// Sign with the modern deterministic scheme
	scheme, err := mina.NewModernScheme(mina.TestNet, privateKey)
	require.NoError(t, err)
	signer, err := scheme.Signer(privateKey)
	require.NoError(t, err)
	sig, err := signer.Sign(msg)
	require.NoError(t, err)
	rx, err := sig.R.AffineX()
	require.NoError(t, err)

	// Both signature components must match the values produced by o1js
	require.Equal(t, "7498211454887732397611383458525771335202225150210033989140532814046175202217", new(big.Int).SetBytes(rx.Bytes()).String())
	require.Equal(t, "23762402591548773360210428794470580958875631188711561453643273665286945952714", new(big.Int).SetBytes(sig.S.Bytes()).String())

	t.Log("✓ Modern signature matches the o1js packed-input vector")
}

// TestLegacyAndModernSignaturesDoNotCrossVerify verifies flavor separation.
func TestLegacyAndModernSignaturesDoNotCrossVerify(t *testing.T) {
	t.Parallel()
	// Create a shared private key and field message
	privateKey, err := mina.NewPrivateKey(pasta.NewPallasScalarField().FromUint64(1))
	require.NoError(t, err)
	msg := new(mina.ROInput).Init()
	msg.AddFields(pasta.NewPallasBaseField().FromUint64(42))

	// Create a legacy signature
	legacyScheme, err := mina.NewScheme(mina.TestNet, privateKey)
	require.NoError(t, err)
	legacySigner, err := legacyScheme.Signer(privateKey)
	require.NoError(t, err)
	legacySignature, err := legacySigner.Sign(msg)
	require.NoError(t, err)

	// Create a modern signature
	modernScheme, err := mina.NewModernScheme(mina.TestNet, privateKey)
	require.NoError(t, err)
	modernSigner, err := modernScheme.Signer(privateKey)
	require.NoError(t, err)
	modernSignature, err := modernSigner.Sign(msg)
	require.NoError(t, err)

	// A modern verifier must reject the legacy signature
	modernVerifierScheme, err := mina.NewModernRandomisedScheme(mina.TestNet, pcg.NewRandomised())
	require.NoError(t, err)
	modernVerifier, err := modernVerifierScheme.Verifier()
	require.NoError(t, err)
	require.Error(t, modernVerifier.Verify(legacySignature, privateKey.PublicKey(), msg))

	// A legacy verifier must reject the modern signature
	legacyVerifierScheme, err := mina.NewRandomisedScheme(mina.TestNet, pcg.NewRandomised())
	require.NoError(t, err)
	legacyVerifier, err := legacyVerifierScheme.Verifier()
	require.NoError(t, err)
	require.Error(t, legacyVerifier.Verify(modernSignature, privateKey.PublicKey(), msg))

	t.Log("✓ Legacy and modern signatures do not cross-verify")
}

// TestModernDevNetEqualsTestNet verifies o1js network alias compatibility.
func TestModernDevNetEqualsTestNet(t *testing.T) {
	t.Parallel()
	// Create a shared private key and field message
	privateKey, err := mina.NewPrivateKey(pasta.NewPallasScalarField().FromUint64(1))
	require.NoError(t, err)
	msg := new(mina.ROInput).Init()
	msg.AddFields(pasta.NewPallasBaseField().FromUint64(42))

	// Sign the same message for testnet and devnet
	sign := func(network mina.NetworkID) []byte {
		scheme, err := mina.NewModernScheme(network, privateKey)
		require.NoError(t, err)
		signer, err := scheme.Signer(privateKey)
		require.NoError(t, err)
		sig, err := signer.Sign(msg)
		require.NoError(t, err)
		serialized, err := mina.SerializeSignature(sig)
		require.NoError(t, err)
		return serialized
	}

	// o1js treats devnet and testnet as the same signature domain
	require.Equal(t, sign(mina.TestNet), sign(mina.DevNet))

	t.Log("✓ Modern devnet and testnet signatures are identical")
}
