package signing_test

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17/keygen/dkg/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17/signing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

// TestLindell17DKGAndSign tests the complete DKG and signing flow
func TestLindell17DKGAndSign(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		threshold uint
		total     uint
	}{
		{"2of2", 2, 2},
		{"2of3", 2, 3},
		{"2of5", 2, 5},
	}

	// Test with K256 (secp256k1)
	t.Run("K256", func(t *testing.T) {
		t.Parallel()
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestWithCurve(t, k256.NewCurve(), tc.threshold, tc.total)
			})
		}
	})

	// Test with P256 (secp256r1)
	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestWithCurve(t, p256.NewCurve(), tc.threshold, tc.total)
			})
		}
	})
}

func runTestWithCurve[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	t *testing.T,
	curve ecdsa.Curve[P, B, S],
	threshold uint,
	total uint,
) {
	t.Helper()

	// Setup
	prng := crand.Reader
	var sid network.SID
	_, err := io.ReadFull(prng, sid[:])
	require.NoError(t, err)

	// Create access structure
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := sharing.ID(0); i < sharing.ID(total); i++ {
		shareholders.Add(i)
	}
	accessStructure, err := shamir.NewAccessStructure(threshold, shareholders.Freeze())
	require.NoError(t, err)

	// Run DKG
	shards := testutils.RunLindell17DKG(t, curve, accessStructure)
	require.Equal(t, int(total), len(shards))

	// Test signing with different pairs
	t.Run("threshold_signing", func(t *testing.T) {
		// For Lindell17, threshold must be 2, so we test pairwise signing
		// Test signing with the first pair (0, 1)
		primaryID := sharing.ID(0)
		secondaryID := sharing.ID(1)

		message := []byte("Hello, Lindell17 ECDSA!")

		signature := runSigningSession(t, curve, shards[primaryID], shards[secondaryID], primaryID, secondaryID, message, prng)

		// Verify the signature
		suite, err := ecdsa.NewSuite(curve, sha256.New)
		require.NoError(t, err)
		ecdsaScheme, err := ecdsa.NewScheme(suite, prng)
		require.NoError(t, err)
		verifier, err := ecdsaScheme.Verifier()
		require.NoError(t, err)

		err = verifier.Verify(signature, shards[primaryID].PublicKey(), message)
		require.NoError(t, err)

		t.Logf("✓ Lindell17 threshold signing works! Successfully signed and verified a message using 2-party ECDSA.")
	})

	// Test with multiple pairs if we have more than 2 parties
	if total > 2 {
		t.Run("different_pairs", func(t *testing.T) {
			pairs := []struct {
				primary   sharing.ID
				secondary sharing.ID
			}{
				{0, 1},
				{0, 2},
				{1, 2},
			}

			for _, pair := range pairs {
				t.Run(hex.EncodeToString([]byte{byte(pair.primary), byte(pair.secondary)}), func(t *testing.T) {
					message := []byte("Test message for different pairs")

					signature := runSigningSession(t, curve, shards[pair.primary], shards[pair.secondary], pair.primary, pair.secondary, message, prng)

					// Verify
					suite, err := ecdsa.NewSuite(curve, sha256.New)
					require.NoError(t, err)
					ecdsaScheme, err := ecdsa.NewScheme(suite, prng)
					require.NoError(t, err)
					verifier, err := ecdsaScheme.Verifier()
					require.NoError(t, err)

					err = verifier.Verify(signature, shards[pair.primary].PublicKey(), message)
					require.NoError(t, err)

					t.Logf("✓ Successfully signed with pair (%d, %d)", pair.primary, pair.secondary)
				})
			}
		})
	}
}

func runSigningSession[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	t *testing.T,
	curve ecdsa.Curve[P, B, S],
	primaryShard, secondaryShard *lindell17.Shard[P, B, S],
	primaryID, secondaryID sharing.ID,
	message []byte,
	prng io.Reader,
) *ecdsa.Signature[S] {
	t.Helper()

	// Create signing session ID
	var signingSID network.SID
	_, err := io.ReadFull(prng, signingSID[:])
	require.NoError(t, err)

	tape := hagrid.NewTranscript(hex.EncodeToString(signingSID[:]))

	// Create suite
	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)

	// Create primary and secondary cosigners with cloned tapes
	primaryCosigner, err := signing.NewPrimaryCosigner(
		signingSID,
		suite,
		secondaryID,
		primaryShard,
		fiatshamir.Name,
		tape.Clone(),
		prng,
	)
	require.NoError(t, err)

	secondaryCosigner, err := signing.NewSecondaryCosigner(
		signingSID,
		suite,
		primaryID,
		secondaryShard,
		fiatshamir.Name,
		tape.Clone(),
		prng,
	)
	require.NoError(t, err)

	// Round 1: Primary -> Secondary
	r1out, err := primaryCosigner.Round1()
	require.NoError(t, err)
	require.NotNil(t, r1out)

	// Round 2: Secondary -> Primary
	r2out, err := secondaryCosigner.Round2(r1out)
	require.NoError(t, err)
	require.NotNil(t, r2out)
	require.NotNil(t, r2out.BigR2)
	require.NotNil(t, r2out.BigR2Proof)

	// Round 3: Primary -> Secondary
	r3out, err := primaryCosigner.Round3(r2out)
	require.NoError(t, err)
	require.NotNil(t, r3out)
	require.NotNil(t, r3out.BigR1)
	require.NotNil(t, r3out.BigR1Proof)

	// Round 4: Secondary -> Primary
	r4out, err := secondaryCosigner.Round4(r3out, message)
	require.NoError(t, err)
	require.NotNil(t, r4out)
	require.NotNil(t, r4out.C3)

	// Round 5: Primary produces final signature
	signature, err := primaryCosigner.Round5(r4out, message)
	require.NoError(t, err)
	require.NotNil(t, signature)
	require.NotNil(t, signature.R)
	require.NotNil(t, signature.S)

	return signature
}

// TestLindell17EdgeCases tests edge cases like empty messages, large messages
func TestLindell17EdgeCases(t *testing.T) {
	t.Parallel()

	// Test cases
	testCases := []struct {
		name    string
		message []byte
	}{
		{"empty_message", []byte{}},
		{"single_byte", []byte{0x42}},
		{"all_zeros", make([]byte, 32)},
		{"all_ones", bytes.Repeat([]byte{0xFF}, 32)},
		{"large_message", make([]byte, 1024)},
	}

	// Fill large message with random data
	crand.Read(testCases[4].message)

	t.Run("K256", func(t *testing.T) {
		t.Parallel()
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				testEdgeCaseWithCurve(t, k256.NewCurve(), tc.message)
			})
		}
	})

	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				testEdgeCaseWithCurve(t, p256.NewCurve(), tc.message)
			})
		}
	})
}

func testEdgeCaseWithCurve[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	t *testing.T,
	curve ecdsa.Curve[P, B, S],
	message []byte,
) {
	t.Helper()

	threshold := uint(2)
	total := uint(3)
	prng := crand.Reader

	// Setup
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := sharing.ID(0); i < sharing.ID(total); i++ {
		shareholders.Add(i)
	}
	accessStructure, err := shamir.NewAccessStructure(threshold, shareholders.Freeze())
	require.NoError(t, err)

	// Run DKG
	shards := testutils.RunLindell17DKG(t, curve, accessStructure)

	// Sign with first pair
	signature := runSigningSession(t, curve, shards[0], shards[1], 0, 1, message, prng)

	// Verify
	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)
	ecdsaScheme, err := ecdsa.NewScheme(suite, prng)
	require.NoError(t, err)
	verifier, err := ecdsaScheme.Verifier()
	require.NoError(t, err)

	err = verifier.Verify(signature, shards[0].PublicKey(), message)
	require.NoError(t, err)

	t.Logf("✓ Successfully signed edge case message")
}

// TestLindell17ConcurrentSigning tests signing multiple messages concurrently
func TestLindell17ConcurrentSigning(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	numMessages := 5

	t.Run("K256", func(t *testing.T) {
		t.Parallel()
		testConcurrentSigningWithCurve(t, k256.NewCurve(), threshold, total, numMessages)
	})

	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		testConcurrentSigningWithCurve(t, p256.NewCurve(), threshold, total, numMessages)
	})
}

func testConcurrentSigningWithCurve[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	t *testing.T,
	curve ecdsa.Curve[P, B, S],
	threshold uint,
	total uint,
	numMessages int,
) {
	t.Helper()

	prng := crand.Reader

	// Setup
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := sharing.ID(0); i < sharing.ID(total); i++ {
		shareholders.Add(i)
	}
	accessStructure, err := shamir.NewAccessStructure(threshold, shareholders.Freeze())
	require.NoError(t, err)

	// Run DKG
	shards := testutils.RunLindell17DKG(t, curve, accessStructure)

	// Generate multiple messages
	messages := make([][]byte, numMessages)
	for i := range numMessages {
		messages[i] = []byte(string(rune('A' + i)))
	}

	// Sign messages concurrently
	var wg sync.WaitGroup
	type result struct {
		index int
		sig   *ecdsa.Signature[S]
		err   error
	}
	results := make(chan result, numMessages)

	for i := range numMessages {
		wg.Add(1)
		go func(index int, message []byte) {
			defer wg.Done()

			sig := runSigningSession(t, curve, shards[0], shards[1], 0, 1, message, prng)
			results <- result{index, sig, nil}
		}(i, messages[i])
	}

	wg.Wait()
	close(results)

	// Verify all signatures
	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)
	ecdsaScheme, err := ecdsa.NewScheme(suite, prng)
	require.NoError(t, err)
	verifier, err := ecdsaScheme.Verifier()
	require.NoError(t, err)

	count := 0
	for result := range results {
		require.NoError(t, result.err, "signing message %d failed", result.index)
		require.NotNil(t, result.sig)

		err = verifier.Verify(result.sig, shards[0].PublicKey(), messages[result.index])
		require.NoError(t, err, "signature verification failed for message %d", result.index)
		count++
	}

	require.Equal(t, numMessages, count)
	t.Logf("✓ Successfully signed %d messages concurrently", numMessages)
}

// TestLindell17InvalidProof tests that invalid proofs are rejected
func TestLindell17InvalidProof(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)

	t.Run("K256", func(t *testing.T) {
		t.Parallel()
		testInvalidProofWithCurve(t, k256.NewCurve(), threshold, total)
	})

	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		testInvalidProofWithCurve(t, p256.NewCurve(), threshold, total)
	})
}

func testInvalidProofWithCurve[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	t *testing.T,
	curve ecdsa.Curve[P, B, S],
	threshold uint,
	total uint,
) {
	t.Helper()

	prng := crand.Reader

	// Setup
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := sharing.ID(0); i < sharing.ID(total); i++ {
		shareholders.Add(i)
	}
	accessStructure, err := shamir.NewAccessStructure(threshold, shareholders.Freeze())
	require.NoError(t, err)

	// Run DKG
	shards := testutils.RunLindell17DKG(t, curve, accessStructure)

	primaryID := sharing.ID(0)
	secondaryID := sharing.ID(1)

	// Create signing session ID
	var signingSID network.SID
	_, err = io.ReadFull(prng, signingSID[:])
	require.NoError(t, err)

	tape := hagrid.NewTranscript(hex.EncodeToString(signingSID[:]))

	// Create suite
	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)

	// Create primary and secondary cosigners
	primaryCosigner, err := signing.NewPrimaryCosigner(
		signingSID,
		suite,
		secondaryID,
		shards[primaryID],
		fiatshamir.Name,
		tape.Clone(),
		prng,
	)
	require.NoError(t, err)

	secondaryCosigner, err := signing.NewSecondaryCosigner(
		signingSID,
		suite,
		primaryID,
		shards[secondaryID],
		fiatshamir.Name,
		tape.Clone(),
		prng,
	)
	require.NoError(t, err)

	// Round 1: Primary -> Secondary
	r1out, err := primaryCosigner.Round1()
	require.NoError(t, err)

	// Round 2: Secondary -> Primary
	r2out, err := secondaryCosigner.Round2(r1out)
	require.NoError(t, err)

	// Corrupt the R2 point to make proof verification fail
	r2out.BigR2 = r2out.BigR2.Neg()

	// Round 3: Primary should reject corrupted proof
	_, err = primaryCosigner.Round3(r2out)
	require.Error(t, err)
	require.Contains(t, err.Error(), "verify")

	t.Logf("✓ Successfully detected invalid proof")
}

// TestLindell17InvalidCommitment tests that invalid commitment opening is rejected
func TestLindell17InvalidCommitment(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)

	t.Run("K256", func(t *testing.T) {
		t.Parallel()
		testInvalidCommitmentWithCurve(t, k256.NewCurve(), threshold, total)
	})

	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		testInvalidCommitmentWithCurve(t, p256.NewCurve(), threshold, total)
	})
}

func testInvalidCommitmentWithCurve[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	t *testing.T,
	curve ecdsa.Curve[P, B, S],
	threshold uint,
	total uint,
) {
	t.Helper()

	prng := crand.Reader

	// Setup
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := sharing.ID(0); i < sharing.ID(total); i++ {
		shareholders.Add(i)
	}
	accessStructure, err := shamir.NewAccessStructure(threshold, shareholders.Freeze())
	require.NoError(t, err)

	// Run DKG
	shards := testutils.RunLindell17DKG(t, curve, accessStructure)

	primaryID := sharing.ID(0)
	secondaryID := sharing.ID(1)
	message := []byte("Test message")

	// Create signing session ID
	var signingSID network.SID
	_, err = io.ReadFull(prng, signingSID[:])
	require.NoError(t, err)

	tape := hagrid.NewTranscript(hex.EncodeToString(signingSID[:]))

	// Create suite
	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)

	// Create primary and secondary cosigners
	primaryCosigner, err := signing.NewPrimaryCosigner(
		signingSID,
		suite,
		secondaryID,
		shards[primaryID],
		fiatshamir.Name,
		tape.Clone(),
		prng,
	)
	require.NoError(t, err)

	secondaryCosigner, err := signing.NewSecondaryCosigner(
		signingSID,
		suite,
		primaryID,
		shards[secondaryID],
		fiatshamir.Name,
		tape.Clone(),
		prng,
	)
	require.NoError(t, err)

	// Round 1: Primary -> Secondary
	r1out, err := primaryCosigner.Round1()
	require.NoError(t, err)

	// Round 2: Secondary -> Primary
	r2out, err := secondaryCosigner.Round2(r1out)
	require.NoError(t, err)

	// Round 3: Primary -> Secondary
	r3out, err := primaryCosigner.Round3(r2out)
	require.NoError(t, err)

	// Corrupt the R1 opening to make commitment verification fail
	r3out.BigR1 = r3out.BigR1.Neg()

	// Round 4: Secondary should reject invalid commitment opening
	_, err = secondaryCosigner.Round4(r3out, message)
	require.Error(t, err)
	require.Contains(t, err.Error(), "commitment")

	t.Logf("✓ Successfully detected invalid commitment opening")
}

// BenchmarkLindell17Signing benchmarks the performance of the protocol
func BenchmarkLindell17Signing(b *testing.B) {
	// Setup
	threshold := uint(2)
	total := uint(3)
	curve := k256.NewCurve()
	prng := crand.Reader

	shareholders := hashset.NewComparable[sharing.ID]()
	for i := sharing.ID(0); i < sharing.ID(total); i++ {
		shareholders.Add(i)
	}
	accessStructure, err := shamir.NewAccessStructure(threshold, shareholders.Freeze())
	if err != nil {
		b.Fatal(err)
	}

	// Run DKG
	shards := testutils.RunLindell17DKG(b, curve, accessStructure)
	message := []byte("Benchmark message")

	b.ResetTimer()
	for range b.N {
		runSigningSession(&testing.T{}, curve, shards[0], shards[1], 0, 1, message, prng)
	}
}
