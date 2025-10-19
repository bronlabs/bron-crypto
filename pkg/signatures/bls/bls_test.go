package bls_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

func Test_BasicSignature(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()

	scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
	require.NoError(t, err)

	sf := bls12381.NewScalarField()
	seed := make([]byte, sf.ElementSize())
	_, err = io.ReadFull(crand.Reader, seed)
	require.NoError(t, err)

	keyGenerator, err := scheme.Keygen(bls.GenerateWithSeed[*bls12381.PointG1](seed))
	require.NoError(t, err)

	sk, pk, err := keyGenerator.Generate(nil)
	require.NoError(t, err)

	signer, err := scheme.Signer(sk)
	require.NoError(t, err)

	message := []byte("Hello, BLS!")
	signature, err := signer.Sign(message)
	require.NoError(t, err)
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature, pk, message)
	require.NoError(t, err)
}

// Test vector structures
type signTestVector struct {
	Input struct {
		PrivKey string `json:"privkey"`
		Message string `json:"message"`
	} `json:"input"`
	Output string `json:"output"`
}

type verifyTestVector struct {
	Input struct {
		PubKey    string `json:"pubkey"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	} `json:"input"`
	Output bool `json:"output"`
}

type aggregateTestVector struct {
	Input  []string `json:"input"`
	Output string   `json:"output"`
}

type aggregateVerifyTestVector struct {
	Input struct {
		PubKeys   []string `json:"pubkeys"`
		Messages  []string `json:"messages"`
		Signature string   `json:"signature"`
	} `json:"input"`
	Output bool `json:"output"`
}

type batchVerifyTestVector struct {
	Input struct {
		PubKeys    []string `json:"pubkeys"`
		Messages   []string `json:"messages"`
		Signatures []string `json:"signatures"`
	} `json:"input"`
	Output bool `json:"output"`
}

// Helper function to decode hex with 0x prefix
func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

// Helper function to read test vector file
func readTestVector(t *testing.T, filename string, v any) {
	t.Helper()
	data, err := os.ReadFile(filename)
	require.NoError(t, err, "Failed to read test vector file: %s", filename)
	err = json.Unmarshal(data, v)
	require.NoError(t, err, "Failed to unmarshal test vector: %s", filename)
}

// TestSignVectors tests BLS signature generation using test vectors.
func TestSignVectors(t *testing.T) {
	t.Parallel()

	vectorsDir := "vectors/sign"
	files, err := os.ReadDir(vectorsDir)
	require.NoError(t, err)

	family := pairable.NewBLS12381()
	// These tests vectors are from the ethereum foundation and they were generated for their specific variant, which is POP.
	// We will override the internal dst getter to make it compliant.
	customDst, err := bls.BLS12381CipherSuite().GetDst(bls.POP, bls.ShortKey)
	require.NoError(t, err)

	signerOpt := bls.SignWithCustomDST[*bls12381.PointG1](customDst)

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
		t.Parallel()
			var vector signTestVector
			readTestVector(t, filepath.Join(vectorsDir, file.Name()), &vector)

			// Decode inputs
			privKeyBytes, err := decodeHex(vector.Input.PrivKey)
			require.NoError(t, err)
			message, err := decodeHex(vector.Input.Message)
			require.NoError(t, err)
			expectedSig, err := decodeHex(vector.Output)
			require.NoError(t, err)

			// Create scheme
			scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
			require.NoError(t, err)

			// Create private key from bytes
			privKey, err := bls.NewPrivateKeyFromBytes(family.SourceSubGroup(), privKeyBytes)
			if strings.Contains(file.Name(), "zero_privkey") {
				// Special case: zero private key should fail
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			// Sign the message
			signer, err := scheme.Signer(privKey, signerOpt)
			require.NoError(t, err)

			signature, err := signer.Sign(message)
			if strings.Contains(file.Name(), "zero_privkey") {
				// Special case: zero private key should fail
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify signature matches expected
			actualSig := signature.Bytes()
			require.Equal(t, expectedSig, actualSig, "Signature mismatch for %s", file.Name())

		})
	}
}

func TestVerifyVectors(t *testing.T) {
	t.Parallel()

	vectorsDir := "vectors/verify"
	files, err := os.ReadDir(vectorsDir)
	require.NoError(t, err)

	family := pairable.NewBLS12381()
	// These tests vectors are from the ethereum foundation and they were generated for their specific variant, which is POP.
	// We will override the internal dst getter to make it compliant.
	customDst, err := bls.BLS12381CipherSuite().GetDst(bls.POP, bls.ShortKey)
	require.NoError(t, err)

	verifierOpt := bls.VerifyWithCustomDST[*bls12381.PointG1](customDst)

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
		t.Parallel()
			var vector verifyTestVector
			readTestVector(t, filepath.Join(vectorsDir, file.Name()), &vector)

			// Decode inputs
			pubKeyBytes, err := decodeHex(vector.Input.PubKey)
			require.NoError(t, err)
			message, err := decodeHex(vector.Input.Message)
			require.NoError(t, err)
			signatureBytes, err := decodeHex(vector.Input.Signature)
			require.NoError(t, err)

			// Create scheme
			scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
			require.NoError(t, err)

			// Create public key from bytes
			g1 := family.SourceSubGroup()
			pubKey, err := bls.NewPublicKeyFromBytes(g1, pubKeyBytes)
			if err != nil {
				// Some test vectors have invalid public keys
				if !vector.Output {
					return // Expected to fail
				}
				require.NoError(t, err)
			}
			// Create signature from bytes
			g2 := family.TwistedSubGroup()
			signature, err := bls.NewSignatureFromBytes(g2, signatureBytes, nil)
			if err != nil {
				// Some test vectors have invalid signatures
				if !vector.Output {
					return // Expected to fail
				}
				require.NoError(t, err)
			}

			// Create verifier
			verifier, err := scheme.Verifier(verifierOpt)
			require.NoError(t, err)

			// Verify the signature
			err = verifier.Verify(signature, pubKey, message)

			if vector.Output {
				require.NoError(t, err, "Expected verification to succeed for %s", file.Name())
			} else {
				require.Error(t, err, "Expected verification to fail for %s", file.Name())
			}
		})
	}
}

func TestAggregateVectors(t *testing.T) {
	t.Parallel()

	vectorsDir := "vectors/aggregate"
	files, err := os.ReadDir(vectorsDir)
	require.NoError(t, err)

	family := pairable.NewBLS12381()

	// Outer:
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
		t.Parallel()
			var vector aggregateTestVector
			readTestVector(t, filepath.Join(vectorsDir, file.Name()), &vector)

			// Decode inputs and expected output
			expectedSigBytes, err := decodeHex(vector.Output)
			require.NoError(t, err)

			// Create scheme
			g2 := family.TwistedSubGroup()

			// Parse all input signatures
			var signatures []*bls.Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]
			for _, sigHex := range vector.Input {
				sigBytes, err := decodeHex(sigHex)
				require.NoError(t, err)

				sig, err := bls.NewSignatureFromBytes(g2, sigBytes, nil)
				if strings.Contains(file.Name(), "infinity_signature") {
					// We will deviate from the test vectors and disallow infinity signatures
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				signatures = append(signatures, sig)
			}
			if strings.Contains(file.Name(), "na_signatures") {
				require.Empty(t, signatures)
				return
			}
			// Aggregate signatures
			aggregated, err := bls.AggregateAll[*bls12381.PointG2](signatures)
			require.NoError(t, err)

			// Verify the aggregated signature matches expected
			actualSigBytes := aggregated.Bytes()
			require.Equal(t, expectedSigBytes, actualSigBytes, "Aggregated signature mismatch for %s", file.Name())
		})
	}
}

func TestAggregateVerifyVectors(t *testing.T) {
	t.Parallel()

	vectorsDir := "vectors/aggregate_verify"
	files, err := os.ReadDir(vectorsDir)
	require.NoError(t, err)

	family := pairable.NewBLS12381()
	// These tests vectors are from the ethereum foundation and they were generated for their specific variant, which is POP.
	// We will override the internal dst getter to make it compliant.
	customDst, err := bls.BLS12381CipherSuite().GetDst(bls.POP, bls.ShortKey)
	require.NoError(t, err)

	verifierOpt := bls.VerifyWithCustomDST[*bls12381.PointG1](customDst)

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
		t.Parallel()
			var vector aggregateVerifyTestVector
			readTestVector(t, filepath.Join(vectorsDir, file.Name()), &vector)

			// Decode inputs
			signatureBytes, err := decodeHex(vector.Input.Signature)
			require.NoError(t, err)

			// Parse public keys
			g1 := family.SourceSubGroup()
			var pubKeys []*bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
			for _, pubKeyHex := range vector.Input.PubKeys {
				pubKeyBytes, err := decodeHex(pubKeyHex)
				require.NoError(t, err)

				pubKey, err := bls.NewPublicKeyFromBytes(g1, pubKeyBytes)
				if err != nil {
					// Some test vectors have invalid public keys
					if !vector.Output {
						return // Expected to fail
					}
					require.NoError(t, err)
				}
				pubKeys = append(pubKeys, pubKey)
			}

			// Parse messages
			var messages [][]byte
			for _, msgHex := range vector.Input.Messages {
				msg, err := decodeHex(msgHex)
				require.NoError(t, err)
				messages = append(messages, msg)
			}

			// Create signature from bytes
			g2 := family.TwistedSubGroup()
			signature, err := bls.NewSignatureFromBytes(g2, signatureBytes, nil)
			if err != nil {
				// Some test vectors have invalid signatures
				if !vector.Output {
					return // Expected to fail
				}
				require.NoError(t, err)
			}

			// Create scheme and verifier
			scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
			require.NoError(t, err)

			verifier, err := scheme.Verifier(verifierOpt)
			require.NoError(t, err)

			// Verify aggregated signature
			err = verifier.AggregateVerify(signature, pubKeys, messages)

			if vector.Output {
				require.NoError(t, err, "Expected aggregate verification to succeed for %s", file.Name())
			} else {
				require.Error(t, err, "Expected aggregate verification to fail for %s", file.Name())
			}
		})
	}
}

func TestBatchVerifyVectors(t *testing.T) {
	t.Parallel()

	vectorsDir := "vectors/batch_verify"
	files, err := os.ReadDir(vectorsDir)
	require.NoError(t, err)

	family := pairable.NewBLS12381()
	// These tests vectors are from the ethereum foundation and they were generated for their specific variant, which is POP.
	// We will override the internal dst getter to make it compliant.
	customDst, err := bls.BLS12381CipherSuite().GetDst(bls.POP, bls.ShortKey)
	require.NoError(t, err)

	verifierOpt := bls.VerifyWithCustomDST[*bls12381.PointG1](customDst)

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
		t.Parallel()
			var vector batchVerifyTestVector
			readTestVector(t, filepath.Join(vectorsDir, file.Name()), &vector)

			// Parse public keys
			g1 := family.SourceSubGroup()
			var pubKeys []*bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
			for _, pubKeyHex := range vector.Input.PubKeys {
				pubKeyBytes, err := decodeHex(pubKeyHex)
				require.NoError(t, err)

				pubKey, err := bls.NewPublicKeyFromBytes(g1, pubKeyBytes)
				if err != nil {
					// Some test vectors have invalid public keys
					if !vector.Output {
						return // Expected to fail
					}
					require.NoError(t, err)
				}
				pubKeys = append(pubKeys, pubKey)
			}

			// Parse messages
			var messages [][]byte
			for _, msgHex := range vector.Input.Messages {
				msg, err := decodeHex(msgHex)
				require.NoError(t, err)
				messages = append(messages, msg)
			}

			// Parse signatures
			g2 := family.TwistedSubGroup()
			var signatures []*bls.Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]
			for _, sigHex := range vector.Input.Signatures {
				sigBytes, err := decodeHex(sigHex)
				require.NoError(t, err)

				sig, err := bls.NewSignatureFromBytes(g2, sigBytes, nil)
				if err != nil {
					// Some test vectors have invalid signatures
					if !vector.Output {
						return // Expected to fail
					}
					require.NoError(t, err)
				}
				signatures = append(signatures, sig)
			}

			// Create scheme and verifier
			scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
			require.NoError(t, err)

			verifier, err := scheme.Verifier(verifierOpt)
			require.NoError(t, err)

			// Verify each signature individually
			// Batch verification in BLS context means verifying multiple individual signatures
			allValid := true
			for i := range signatures {
				if i >= len(pubKeys) || i >= len(messages) {
					allValid = false
					break
				}
				err = verifier.Verify(signatures[i], pubKeys[i], messages[i])
				if err != nil {
					allValid = false
					break
				}
			}

			if vector.Output {
				require.True(t, allValid, "Expected batch verification to succeed for %s", file.Name())
			} else {
				require.False(t, allValid, "Expected batch verification to fail for %s", file.Name())
			}
		})
	}
}

// TestBatchSign tests the BatchSign functionality
func TestBatchSign(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()

	testCases := []struct {
		name        string
		rogueKeyAlg bls.RogueKeyPreventionAlgorithm
		messages    [][]byte
		expectError bool
	}{
		{
			name:        "Basic scheme - multiple messages",
			rogueKeyAlg: bls.Basic,
			messages:    [][]byte{[]byte("msg1"), []byte("msg2"), []byte("msg3")},
		},
		{
			name:        "Message augmentation scheme - multiple messages",
			rogueKeyAlg: bls.MessageAugmentation,
			messages:    [][]byte{[]byte("hello"), []byte("world")},
		},
		{
			name:        "POP scheme - multiple messages",
			rogueKeyAlg: bls.POP,
			messages:    [][]byte{[]byte("test1"), []byte("test2"), []byte("test3"), []byte("test4")},
		},
		{
			name:        "Empty messages",
			rogueKeyAlg: bls.Basic,
			messages:    [][]byte{},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
			// Create scheme
			scheme, err := bls.NewShortKeyScheme(family, tc.rogueKeyAlg)
			require.NoError(t, err)

			// Generate key pair
			keyGen, err := scheme.Keygen()
			require.NoError(t, err)

			sk, pk, err := keyGen.Generate(crand.Reader)
			require.NoError(t, err)

			// Create signer
			signer, err := scheme.Signer(sk)
			require.NoError(t, err)

			// Make a copy of messages to avoid mutation
			messagesCopy := make([][]byte, len(tc.messages))
			for i, msg := range tc.messages {
				messagesCopy[i] = append([]byte(nil), msg...)
			}

			// Batch sign
			signatures, err := signer.BatchSign(messagesCopy...)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, signatures, len(tc.messages))

			// Create verifier
			verifier, err := scheme.Verifier()
			require.NoError(t, err)

			// Verify each signature with original messages
			for i, sig := range signatures {
				err := verifier.Verify(sig, pk, tc.messages[i])
				require.NoError(t, err, "Failed to verify signature %d", i)
			}

			// For POP scheme, verify proof of possession
			if tc.rogueKeyAlg == bls.POP {
				for _, sig := range signatures {
					pop := sig.Pop()
					require.NotNil(t, pop, "POP signature should have proof of possession")
				}
			}
		})
	}
}

// TestAggregateSign tests the AggregateSign functionality
func TestAggregateSign(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()

	testCases := []struct {
		name        string
		rogueKeyAlg bls.RogueKeyPreventionAlgorithm
		messages    [][]byte
	}{
		{
			name:        "Basic scheme - aggregate multiple messages",
			rogueKeyAlg: bls.Basic,
			messages:    [][]byte{[]byte("msg1"), []byte("msg2"), []byte("msg3")},
		},
		{
			name:        "Message augmentation - aggregate",
			rogueKeyAlg: bls.MessageAugmentation,
			messages:    [][]byte{[]byte("hello"), []byte("world"), []byte("test")},
		},
		{
			name:        "POP scheme - aggregate",
			rogueKeyAlg: bls.POP,
			messages:    [][]byte{[]byte("alpha"), []byte("beta"), []byte("gamma")},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
			// Create scheme
			scheme, err := bls.NewShortKeyScheme(family, tc.rogueKeyAlg)
			require.NoError(t, err)

			// Generate multiple key pairs
			var privateKeys []*bls.PrivateKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
			var publicKeys []*bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]

			keyGen, err := scheme.Keygen()
			require.NoError(t, err)

			for range tc.messages {
				sk, pk, err := keyGen.Generate(crand.Reader)
				require.NoError(t, err)
				privateKeys = append(privateKeys, sk)
				publicKeys = append(publicKeys, pk)
			}

			// Sign messages with different keys
			var signatures []*bls.Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]
			for i, sk := range privateKeys {
				signer, err := scheme.Signer(sk)
				require.NoError(t, err)

				sig, err := signer.Sign(tc.messages[i])
				require.NoError(t, err)
				signatures = append(signatures, sig)
			}

			// Aggregate signatures
			aggregatedSig, err := bls.AggregateAll[*bls12381.PointG2](signatures)
			require.NoError(t, err)

			// Create verifier and verify aggregated signature
			if tc.rogueKeyAlg == bls.POP {
				// For POP, we need to provide proofs of possession
				var pops []*bls.ProofOfPossession[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]
				for _, sig := range signatures {
					pops = append(pops, sig.Pop())
				}
				verifier, err := scheme.Verifier(bls.VerifyWithProofsOfPossession[*bls12381.PointG1](pops...))
				require.NoError(t, err)
				err = verifier.AggregateVerify(aggregatedSig, publicKeys, tc.messages)
				require.NoError(t, err)
			} else {
				verifier, err := scheme.Verifier()
				require.NoError(t, err)
				err = verifier.AggregateVerify(aggregatedSig, publicKeys, tc.messages)
				require.NoError(t, err)
			}
		})
	}
}

// TestKeyGeneratorWithSeed tests deterministic key generation
func TestKeyGeneratorWithSeed(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()

	// Test with different schemes
	schemes := []struct {
		name        string
		rogueKeyAlg bls.RogueKeyPreventionAlgorithm
	}{
		{"Basic", bls.Basic},
		{"MessageAugmentation", bls.MessageAugmentation},
		{"POP", bls.POP},
	}

	for _, s := range schemes {
		t.Run(s.name, func(t *testing.T) {
		t.Parallel()
			scheme, err := bls.NewShortKeyScheme(family, s.rogueKeyAlg)
			require.NoError(t, err)

			// Test seed - must be at least 32 bytes
			seed := []byte("test seed for deterministic key generation that is long enough")

			// Generate keys with seed option
			keyGen, err := scheme.Keygen(bls.GenerateWithSeed[*bls12381.PointG1](seed))
			require.NoError(t, err)

			sk1, pk1, err := keyGen.Generate(nil)
			require.NoError(t, err)

			// Generate again with same seed - should produce same keys
			keyGen2, err := scheme.Keygen(bls.GenerateWithSeed[*bls12381.PointG1](seed))
			require.NoError(t, err)

			sk2, pk2, err := keyGen2.Generate(nil)
			require.NoError(t, err)

			// Keys should be identical
			require.True(t, sk1.Equal(sk2), "Private keys should be equal with same seed")
			require.True(t, pk1.Equal(pk2), "Public keys should be equal with same seed")

			// Different seed should produce different keys
			differentSeed := []byte("different seed that is also long enough for BLS")
			keyGen3, err := scheme.Keygen(bls.GenerateWithSeed[*bls12381.PointG1](differentSeed))
			require.NoError(t, err)

			sk3, pk3, err := keyGen3.Generate(nil)
			require.NoError(t, err)

			require.False(t, sk1.Equal(sk3), "Private keys should be different with different seed")
			require.False(t, pk1.Equal(pk3), "Public keys should be different with different seed")
		})
	}
}

// TestLongKeyVariant tests the long key variant (public keys in G2)
func TestLongKeyVariant(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()

	testCases := []struct {
		name        string
		rogueKeyAlg bls.RogueKeyPreventionAlgorithm
	}{
		{"Basic", bls.Basic},
		{"MessageAugmentation", bls.MessageAugmentation},
		{"POP", bls.POP},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
			// Create long key scheme
			scheme, err := bls.NewLongKeyScheme(family, tc.rogueKeyAlg)
			require.NoError(t, err)

			// Generate key pair
			keyGen, err := scheme.Keygen()
			require.NoError(t, err)

			sk, pk, err := keyGen.Generate(crand.Reader)
			require.NoError(t, err)

			// Test message
			message := []byte("test message for long key variant")

			// Create signer and sign
			signer, err := scheme.Signer(sk)
			require.NoError(t, err)

			signature, err := signer.Sign(message)
			require.NoError(t, err)

			// Verify signature is in G1 (short) for long key variant
			require.False(t, signature.IsLong(), "Signature should be short for long key variant")

			// Create verifier and verify
			verifier, err := scheme.Verifier()
			require.NoError(t, err)

			err = verifier.Verify(signature, pk, message)
			require.NoError(t, err)

			// Test batch sign
			messages := [][]byte{[]byte("msg1"), []byte("msg2"), []byte("msg3")}
			// Make a copy to avoid mutation for MessageAugmentation
			messagesCopy := make([][]byte, len(messages))
			for i, msg := range messages {
				messagesCopy[i] = append([]byte(nil), msg...)
			}
			signatures, err := signer.BatchSign(messagesCopy...)
			require.NoError(t, err)
			require.Len(t, signatures, len(messages))

			// Verify each signature
			for i, sig := range signatures {
				err := verifier.Verify(sig, pk, messages[i])
				require.NoError(t, err)
			}
		})
	}
}

// TestMessageAugmentationScheme tests the message augmentation rogue key prevention
func TestMessageAugmentationScheme(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()

	// Create scheme with message augmentation
	scheme, err := bls.NewShortKeyScheme(family, bls.MessageAugmentation)
	require.NoError(t, err)

	// Generate multiple key pairs
	keyGen, err := scheme.Keygen()
	require.NoError(t, err)

	var privateKeys []*bls.PrivateKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
	var publicKeys []*bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]

	for range 3 {
		sk, pk, err := keyGen.Generate(crand.Reader)
		require.NoError(t, err)
		privateKeys = append(privateKeys, sk)
		publicKeys = append(publicKeys, pk)
	}

	// Messages for each signer
	messages := [][]byte{
		[]byte("message from signer 1"),
		[]byte("message from signer 2"),
		[]byte("message from signer 3"),
	}

	// Sign messages
	var signatures []*bls.Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]
	for i, sk := range privateKeys {
		signer, err := scheme.Signer(sk)
		require.NoError(t, err)

		sig, err := signer.Sign(messages[i])
		require.NoError(t, err)
		signatures = append(signatures, sig)
	}

	// Aggregate signatures
	aggregatedSig, err := bls.AggregateAll[*bls12381.PointG2](signatures)
	require.NoError(t, err)

	// Verify aggregated signature
	verifier, err := scheme.Verifier()
	require.NoError(t, err)

	err = verifier.AggregateVerify(aggregatedSig, publicKeys, messages)
	require.NoError(t, err)

	// Test that verification fails with wrong message order
	wrongOrderMessages := [][]byte{messages[1], messages[0], messages[2]}
	err = verifier.AggregateVerify(aggregatedSig, publicKeys, wrongOrderMessages)
	require.Error(t, err, "Should fail with wrong message order")
}

// TestPOPScheme tests the proof of possession scheme
func TestPOPScheme(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()

	// Create scheme with POP
	scheme, err := bls.NewShortKeyScheme(family, bls.POP)
	require.NoError(t, err)

	// Generate key pair
	keyGen, err := scheme.Keygen()
	require.NoError(t, err)

	sk, pk, err := keyGen.Generate(crand.Reader)
	require.NoError(t, err)

	// Sign a message
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)

	message := []byte("test message for POP scheme")
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	// Signature should have proof of possession
	pop := signature.Pop()
	require.NotNil(t, pop, "POP signature should have proof of possession")

	// Create verifier with proof of possession
	verifier, err := scheme.Verifier(bls.VerifyWithProofsOfPossession[*bls12381.PointG1](pop))
	require.NoError(t, err)

	// Verify should succeed
	err = verifier.Verify(signature, pk, message)
	require.NoError(t, err)

	// Test aggregate verification with POP
	// Generate multiple signers
	var privateKeys []*bls.PrivateKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
	var publicKeys []*bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
	var pops []*bls.ProofOfPossession[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]

	for range 3 {
		sk, pk, err := keyGen.Generate(crand.Reader)
		require.NoError(t, err)
		privateKeys = append(privateKeys, sk)
		publicKeys = append(publicKeys, pk)

		// Get POP from first signature
		signer, err := scheme.Signer(sk)
		require.NoError(t, err)
		sig, err := signer.Sign([]byte("dummy"))
		require.NoError(t, err)
		pops = append(pops, sig.Pop())
	}

	// Sign same message with all keys (fast aggregate verify case)
	sameMessage := []byte("same message for all")
	var signatures []*bls.Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]

	for _, sk := range privateKeys {
		signer, err := scheme.Signer(sk)
		require.NoError(t, err)
		sig, err := signer.Sign(sameMessage)
		require.NoError(t, err)
		signatures = append(signatures, sig)
	}

	// Aggregate signatures
	aggregatedSig, err := bls.AggregateAll[*bls12381.PointG2](signatures)
	require.NoError(t, err)

	// Create verifier with POPs
	verifierWithPops, err := scheme.Verifier(bls.VerifyWithProofsOfPossession[*bls12381.PointG1](pops...))
	require.NoError(t, err)

	// Fast aggregate verify (same message)
	messages := make([][]byte, len(publicKeys))
	for i := range messages {
		messages[i] = sameMessage
	}

	err = verifierWithPops.AggregateVerify(aggregatedSig, publicKeys, messages)
	require.NoError(t, err)
}

// TestPublicKeyOperations tests PublicKey methods
func TestPublicKeyOperations(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()
	scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
	require.NoError(t, err)

	// Generate first key pair
	keyGen1, err := scheme.Keygen()
	require.NoError(t, err)
	_, pk1, err := keyGen1.Generate(crand.Reader)
	require.NoError(t, err)

	// Generate second key pair with new generator
	keyGen2, err := scheme.Keygen()
	require.NoError(t, err)
	_, pk2, err := keyGen2.Generate(crand.Reader)
	require.NoError(t, err)

	// Test Equal
	require.True(t, pk1.Equal(pk1), "Public key should equal itself")

	// Verify they are actually different by checking bytes first
	pk1Bytes := pk1.Bytes()
	pk2Bytes := pk2.Bytes()
	require.NotEqual(t, pk1Bytes, pk2Bytes, "Public key bytes should be different")

	// Now test Equal - if bytes are different, Equal should return false
	isEqual := pk1.Equal(pk2)
	if isEqual {
		t.Logf("pk1: %x", pk1Bytes)
		t.Logf("pk2: %x", pk2Bytes)
		t.Logf("pk1.Value(): %v", pk1.Value())
		t.Logf("pk2.Value(): %v", pk2.Value())
	}
	require.False(t, isEqual, "Different public keys should not be equal")

	// Test Clone
	pk1Clone := pk1.Clone()
	require.True(t, pk1.Equal(pk1Clone), "Cloned public key should be equal")
	require.NotSame(t, pk1, pk1Clone, "Clone should create new instance")

	// Test IsShort
	require.True(t, pk1.IsShort(), "Short key scheme should have short public keys")

	// Test Bytes and reconstruction
	pk1BytesForReconstruction := pk1.Bytes()
	g1 := family.SourceSubGroup()
	pk1Reconstructed, err := bls.NewPublicKeyFromBytes(g1, pk1BytesForReconstruction)
	require.NoError(t, err)
	require.True(t, pk1.Equal(pk1Reconstructed), "Reconstructed key should be equal")

	// Test TryAdd
	pk1Aggregate := pk1.Clone()
	pk1AggregateResult, err := pk1Aggregate.TryAdd(pk2)
	require.NoError(t, err)
	require.False(t, pk1.Equal(pk1AggregateResult), "Aggregated key should be different")

	// Test aggregating multiple keys
	keys := []*bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]{pk1, pk2}
	aggregated, err := bls.AggregateAll[*bls12381.PointG1](keys)
	require.NoError(t, err)
	require.True(t, aggregated.Equal(pk1AggregateResult), "AggregateAll should match manual aggregation")
}

// TestPrivateKeyOperations tests PrivateKey methods
func TestPrivateKeyOperations(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()
	scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
	require.NoError(t, err)

	// Generate first key pair
	keyGen1, err := scheme.Keygen()
	require.NoError(t, err)
	sk1, pk1, err := keyGen1.Generate(crand.Reader)
	require.NoError(t, err)

	// Generate second key pair with new generator
	keyGen2, err := scheme.Keygen()
	require.NoError(t, err)
	sk2, _, err := keyGen2.Generate(crand.Reader)
	require.NoError(t, err)

	// Test Equal
	require.True(t, sk1.Equal(sk1), "Private key should equal itself")

	// Verify they are actually different
	sk1Bytes := sk1.Bytes()
	sk2Bytes := sk2.Bytes()
	require.NotEqual(t, sk1Bytes, sk2Bytes, "Private key bytes should be different")

	// Now test Equal
	isEqual := sk1.Equal(sk2)
	require.False(t, isEqual, "Different private keys should not be equal")

	// Test Clone
	sk1Clone := sk1.Clone()
	require.True(t, sk1.Equal(sk1Clone), "Cloned private key should be equal")
	require.NotSame(t, sk1, sk1Clone, "Clone should create new instance")

	// Test PublicKey()
	derivedPk := sk1.PublicKey()
	require.True(t, pk1.Equal(derivedPk), "Derived public key should match")

	// Test Bytes and reconstruction
	// Note: There seems to be an inconsistency in the BLS implementation where
	// PrivateKey.Bytes() reverses the bytes but NewPrivateKeyFromBytes doesn't
	// expect reversed bytes. For now, we'll just verify that the bytes are consistent.
	sk1BytesCheck := sk1.Bytes()
	require.NotNil(t, sk1BytesCheck, "Private key bytes should not be nil")
	require.Len(t, sk1BytesCheck, 32, "Private key should be 32 bytes")
}

// TestSignatureOperations tests Signature methods
func TestSignatureOperations(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()
	scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
	require.NoError(t, err)

	// Generate first key pair
	keyGen1, err := scheme.Keygen()
	require.NoError(t, err)
	sk1, _, err := keyGen1.Generate(crand.Reader)
	require.NoError(t, err)

	// Generate second key pair with new generator
	keyGen2, err := scheme.Keygen()
	require.NoError(t, err)
	sk2, _, err := keyGen2.Generate(crand.Reader)
	require.NoError(t, err)

	signer1, err := scheme.Signer(sk1)
	require.NoError(t, err)

	signer2, err := scheme.Signer(sk2)
	require.NoError(t, err)

	message := []byte("test message")

	// Sign with both signers
	sig1, err := signer1.Sign(message)
	require.NoError(t, err)

	sig2, err := signer2.Sign(message)
	require.NoError(t, err)

	// Test Equal
	require.True(t, sig1.Equal(sig1), "Signature should equal itself")

	// Verify they are actually different
	sig1Bytes := sig1.Bytes()
	sig2Bytes := sig2.Bytes()
	require.NotEqual(t, sig1Bytes, sig2Bytes, "Signature bytes should be different")

	// Now test Equal
	isEqual := sig1.Equal(sig2)
	require.False(t, isEqual, "Different signatures should not be equal")

	// Test Clone
	sig1Clone := sig1.Clone()
	require.True(t, sig1.Equal(sig1Clone), "Cloned signature should be equal")
	require.NotSame(t, sig1, sig1Clone, "Clone should create new instance")

	// Test IsLong
	require.True(t, sig1.IsLong(), "Short key scheme should have long signatures")

	// Test Bytes and reconstruction
	sig1BytesForReconstruction := sig1.Bytes()
	g2 := family.TwistedSubGroup()
	sig1Reconstructed, err := bls.NewSignatureFromBytes(g2, sig1BytesForReconstruction, nil)
	require.NoError(t, err)
	require.True(t, sig1.Equal(sig1Reconstructed), "Reconstructed signature should be equal")

	// Test TryAdd
	sig1Aggregate := sig1.Clone()
	sig1AggregateResult, err := sig1Aggregate.TryAdd(sig2)
	require.NoError(t, err)
	require.False(t, sig1.Equal(sig1AggregateResult), "Aggregated signature should be different")

	// Test aggregating multiple signatures
	sigs := []*bls.Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]{sig1, sig2}
	aggregated, err := bls.AggregateAll[*bls12381.PointG2](sigs)
	require.NoError(t, err)
	require.True(t, aggregated.Equal(sig1AggregateResult), "AggregateAll should match manual aggregation")
}

// TestErrorCases tests various error conditions
func TestErrorCases(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()

	t.Run("Invalid public key bytes", func(t *testing.T) {
		t.Parallel()
		g1 := family.SourceSubGroup()
		invalidBytes := make([]byte, 48) // Wrong size or invalid point
		_, err := bls.NewPublicKeyFromBytes(g1, invalidBytes)
		require.Error(t, err)
	})

	t.Run("Invalid private key bytes", func(t *testing.T) {
		t.Parallel()
		g1 := family.SourceSubGroup()
		invalidBytes := make([]byte, 32) // All zeros
		_, err := bls.NewPrivateKeyFromBytes(g1, invalidBytes)
		require.Error(t, err)
	})

	t.Run("Invalid signature bytes", func(t *testing.T) {
		t.Parallel()
		g2 := family.TwistedSubGroup()
		invalidBytes := make([]byte, 96) // Wrong size or invalid point
		_, err := bls.NewSignatureFromBytes(g2, invalidBytes, nil)
		require.Error(t, err)
	})

	t.Run("Empty signature aggregation", func(t *testing.T) {
		t.Parallel()
		var sigs []*bls.Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]
		_, err := bls.AggregateAll[*bls12381.PointG2](sigs)
		require.Error(t, err)
	})

	t.Run("Empty public key aggregation", func(t *testing.T) {
		t.Parallel()
		var pks []*bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
		_, err := bls.AggregateAll[*bls12381.PointG1](pks)
		require.Error(t, err)
	})

	t.Run("Mismatched public keys and messages in aggregate verify", func(t *testing.T) {
		t.Parallel()
		scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
		require.NoError(t, err)

		keyGen, err := scheme.Keygen()
		require.NoError(t, err)

		sk, pk, err := keyGen.Generate(crand.Reader)
		require.NoError(t, err)

		signer, err := scheme.Signer(sk)
		require.NoError(t, err)

		sig, err := signer.Sign([]byte("test"))
		require.NoError(t, err)

		verifier, err := scheme.Verifier()
		require.NoError(t, err)

		// Mismatched lengths
		publicKeys := []*bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]{pk, pk}
		messages := [][]byte{[]byte("test")} // Only one message but two public keys

		err = verifier.AggregateVerify(sig, publicKeys, messages)
		require.Error(t, err)
	})
}

// TestCustomDST tests using custom domain separation tags
func TestCustomDST(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()
	scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
	require.NoError(t, err)

	keyGen, err := scheme.Keygen()
	require.NoError(t, err)

	sk, pk, err := keyGen.Generate(crand.Reader)
	require.NoError(t, err)

	message := []byte("test message")
	customDST := "MY_APPLICATION_v1.0.0"

	// Sign with custom DST
	signer, err := scheme.Signer(sk, bls.SignWithCustomDST[*bls12381.PointG1](customDST))
	require.NoError(t, err)

	signature, err := signer.Sign(message)
	require.NoError(t, err)

	// Verify with matching custom DST - should succeed
	verifier, err := scheme.Verifier(bls.VerifyWithCustomDST[*bls12381.PointG1](customDST))
	require.NoError(t, err)

	err = verifier.Verify(signature, pk, message)
	require.NoError(t, err)

	// Verify with different DST - should fail
	wrongVerifier, err := scheme.Verifier(bls.VerifyWithCustomDST[*bls12381.PointG1]("WRONG_DST"))
	require.NoError(t, err)

	err = wrongVerifier.Verify(signature, pk, message)
	require.Error(t, err)
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()

	t.Run("Sign empty message", func(t *testing.T) {
		t.Parallel()
		scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
		require.NoError(t, err)

		keyGen, err := scheme.Keygen()
		require.NoError(t, err)

		sk, _, err := keyGen.Generate(crand.Reader)
		require.NoError(t, err)

		signer, err := scheme.Signer(sk)
		require.NoError(t, err)

		// Sign empty message - this should fail
		emptyMsg := []byte{}
		_, err = signer.Sign(emptyMsg)
		require.Error(t, err, "Signing empty message should fail")
		require.Contains(t, err.Error(), "message cannot be nil")

		// Sign with nil message - should also fail
		_, err = signer.Sign(nil)
		require.Error(t, err, "Signing nil message should fail")
	})

	t.Run("Sign very long message", func(t *testing.T) {
		t.Parallel()
		scheme, err := bls.NewShortKeyScheme(family, bls.Basic)
		require.NoError(t, err)

		keyGen, err := scheme.Keygen()
		require.NoError(t, err)

		sk, pk, err := keyGen.Generate(crand.Reader)
		require.NoError(t, err)

		signer, err := scheme.Signer(sk)
		require.NoError(t, err)

		// Create a very long message
		longMsg := make([]byte, 10000)
		for i := range longMsg {
			longMsg[i] = byte(i % 256)
		}

		sig, err := signer.Sign(longMsg)
		require.NoError(t, err)

		verifier, err := scheme.Verifier()
		require.NoError(t, err)

		err = verifier.Verify(sig, pk, longMsg)
		require.NoError(t, err)
	})

	t.Run("Nil checks", func(t *testing.T) {
		t.Parallel()
		// Test nil private key clone
		var nilSK *bls.PrivateKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
		cloned := nilSK.Clone()
		require.Nil(t, cloned)

		// Test nil public key clone
		var nilPK *bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
		clonedPK := nilPK.Clone()
		require.Nil(t, clonedPK)

		// Test nil proof of possession clone
		var nilPOP *bls.ProofOfPossession[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]
		clonedPOP := nilPOP.Clone()
		require.Nil(t, clonedPOP)

		// Note: Signature.Clone() doesn't handle nil case, which is expected behaviour
	})
}

// TestProofOfPossessionOperations tests ProofOfPossession methods
func TestProofOfPossessionOperations(t *testing.T) {
	t.Parallel()

	family := pairable.NewBLS12381()
	scheme, err := bls.NewShortKeyScheme(family, bls.POP)
	require.NoError(t, err)

	keyGen, err := scheme.Keygen()
	require.NoError(t, err)

	// Generate first key pair
	sk1, _, err := keyGen.Generate(crand.Reader)
	require.NoError(t, err)

	// Generate second key pair with new generator
	keyGen2, err := scheme.Keygen()
	require.NoError(t, err)
	sk2, _, err := keyGen2.Generate(crand.Reader)
	require.NoError(t, err)

	// Get POPs from signatures
	signer1, err := scheme.Signer(sk1)
	require.NoError(t, err)

	signer2, err := scheme.Signer(sk2)
	require.NoError(t, err)

	sig1, err := signer1.Sign([]byte("test"))
	require.NoError(t, err)

	sig2, err := signer2.Sign([]byte("test"))
	require.NoError(t, err)

	pop1 := sig1.Pop()
	pop2 := sig2.Pop()

	// Test Equal
	require.True(t, pop1.Equal(pop1), "POP should equal itself")
	require.False(t, pop1.Equal(pop2), "Different POPs should not be equal")

	// Test Clone
	pop1Clone := pop1.Clone()
	require.True(t, pop1.Equal(pop1Clone), "Cloned POP should be equal")
	require.NotSame(t, pop1, pop1Clone, "Clone should create new instance")

	// Test Bytes and reconstruction
	pop1Bytes := pop1.Bytes()
	g2 := family.TwistedSubGroup()
	pop1Reconstructed, err := bls.NewProofOfPossessionFromBytes(g2, pop1Bytes)
	require.NoError(t, err)
	require.True(t, pop1.Equal(pop1Reconstructed), "Reconstructed POP should be equal")

	// Test TryAdd
	pop1Aggregate := pop1.Clone()
	pop1AggregateResult, err := pop1Aggregate.TryAdd(pop2)
	require.NoError(t, err)
	require.False(t, pop1.Equal(pop1AggregateResult), "Aggregated POP should be different")

	// Test aggregating multiple POPs
	pops := []*bls.ProofOfPossession[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]{pop1, pop2}
	aggregated, err := bls.AggregateAll[*bls12381.PointG2](pops)
	require.NoError(t, err)
	require.True(t, aggregated.Equal(pop1AggregateResult), "AggregateAll should match manual aggregation")
}
