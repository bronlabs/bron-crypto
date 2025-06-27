package signing_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha3"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/bip340"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22/signing"
	ltu "github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22/testutils"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

// TestLindell22DKGAndSign tests the complete DKG and signing flow
func TestLindell22DKGAndSign(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		threshold uint
		total     uint
	}{
		{"MinimalQuorum_2of3", 2, 3},
		{"StandardQuorum_3of5", 3, 5},
		{"LargerQuorum_5of7", 5, 7},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Setup
			group := k256.NewCurve()
			sid := network.SID(sha3.Sum256([]byte("test-lindell22-dkg-sign-" + tc.name)))
			tape := hagrid.NewTranscript("TestLindell22DKGAndSign")
			prng := pcg.NewRandomised()

			// Create scheme
			scheme, err := bip340.NewScheme(prng)
			require.NoError(t, err)

			// Setup DKG participants
			shareholders := sharing.NewOrdinalShareholderSet(tc.total)
			ac, err := shamir.NewAccessStructure(tc.threshold, shareholders)
			require.NoError(t, err)

			parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, tc.total)
			for id := range shareholders.Iter() {
				p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
				require.NoError(t, err)
				parties = append(parties, p)
			}

			// Run DKG using testutils
			shards, err := ltu.DoLindell22DKG(t, parties)
			require.NoError(t, err)
			require.Equal(t, int(tc.total), shards.Size())

			// Test threshold signing with a quorum
			t.Run("threshold_signing", func(t *testing.T) {
				// Select a quorum (threshold participants)
				quorumSet := hashset.NewComparable[sharing.ID]()
				for i := uint(0); i < tc.threshold; i++ {
					quorumSet.Add(sharing.ID(i))
				}
				quorum := quorumSet.Freeze()

				// Create cosigners using testutils
				signingSID := network.SID(sha3.Sum256([]byte("test-signing-session-" + tc.name)))
				variant, err := scheme.Variant()
				require.NoError(t, err)

				// Convert shards to map for testutils
				shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
				for id, shard := range shards.Iter() {
					shardsMap[id] = shard
				}

				cosigners := ltu.CreateLindell22Cosigners(
					t,
					signingSID,
					shardsMap,
					quorum,
					variant,
					ltu.NewFiatShamirCompiler,
					tape,
					prng,
				)

				// Sign a message using the 3-round protocol
				message := []byte("Hello, Lindell22!")

				// Round 1
				r1bo, err := ltu.DoLindell22Round1(cosigners)
				require.NoError(t, err)

				// Map broadcast outputs to inputs
				participants := make([]networkParticipant, len(cosigners))
				for i, c := range cosigners {
					participants[i] = networkParticipant{c}
				}
				r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

				// Round 2
				r2bo, err := ltu.DoLindell22Round2(cosigners, r2bi)
				require.NoError(t, err)

				// Map broadcast outputs to inputs
				r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

				// Round 3
				partialSigs, err := ltu.DoLindell22Round3(cosigners, r3bi, message)
				require.NoError(t, err)

				// Verify we got partial signatures from all cosigners
				require.Equal(t, len(cosigners), partialSigs.Size())

				// Manual aggregation to test signature validity
				publicMaterial := cosigners[0].Shard().PublicKeyMaterial()

				// Verify we have partial signatures with the expected properties
				for _, psig := range partialSigs.Values() {
					require.NotNil(t, psig)
					require.NotNil(t, psig.Sig.R)
					require.NotNil(t, psig.Sig.S)
					require.NotNil(t, psig.Sig.E)
				}

				// Create aggregator using the public material and scheme
				aggregator, err := signing.NewAggregator(publicMaterial, scheme)
				require.NoError(t, err)

				// Aggregate the partial signatures
				aggregatedSig, err := aggregator.Aggregate(partialSigs.Freeze(), message)
				require.NoError(t, err)
				require.NotNil(t, aggregatedSig)

				// Verify the aggregated signature using the BIP340 scheme
				verifier, err := scheme.Verifier()
				require.NoError(t, err)
				err = verifier.Verify(aggregatedSig, publicMaterial.PublicKey(), message)
				require.NoError(t, err, "threshold signature verification failed")

				t.Log("✅ Lindell22 threshold signing works! Successfully signed and verified a message using the 3-round protocol.")
			})
		})
	}
}

// TestIdentifiableAbort tests the identifiable abort functionality
func TestIdentifiableAbort(t *testing.T) {
	t.Parallel()

	// Setup
	threshold := uint(3)
	total := uint(5)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-identifiable-abort")))
	tape := hagrid.NewTranscript("TestIdentifiableAbort")
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	// Run DKG
	shards, err := ltu.DoLindell22DKG(t, parties)
	require.NoError(t, err)

	// Create signing session
	signingSID := network.SID(sha3.Sum256([]byte("test-signing-abort")))
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := uint(0); i < threshold; i++ {
		quorumSet.Add(sharing.ID(i))
	}
	quorum := quorumSet.Freeze()

	variant, err := scheme.Variant()
	require.NoError(t, err)

	// Convert shards to map for testutils
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards.Iter() {
		shardsMap[id] = shard
	}

	// Create cosigners
	cosigners := ltu.CreateLindell22Cosigners(
		t,
		signingSID,
		shardsMap,
		quorum,
		variant,
		ltu.NewFiatShamirCompiler,
		tape,
		prng,
	)

	message := []byte("Test identifiable abort")

	// Run rounds 1 and 2 normally
	r1bo, err := ltu.DoLindell22Round1(cosigners)
	require.NoError(t, err)

	participants := make([]networkParticipant, len(cosigners))
	for i, c := range cosigners {
		participants[i] = networkParticipant{c}
	}
	r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

	r2bo, err := ltu.DoLindell22Round2(cosigners, r2bi)
	require.NoError(t, err)

	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	// Round 3 - get partial signatures
	partialSigs, err := ltu.DoLindell22Round3(cosigners, r3bi, message)
	require.NoError(t, err)

	// Corrupt one signature
	corruptedID := sharing.ID(1)
	sf := k256.NewScalarField()

	// Get the signature for the corrupted ID and replace it
	validPsig, ok := partialSigs.Get(corruptedID)
	require.True(t, ok)

	corruptedPsig := ltu.CreateCorruptedPartialSignature(t, validPsig, sf)

	// Create a new map with the corrupted signature
	corruptedSigsMap := hashmap.NewComparable[sharing.ID, *lindell22.PartialSignature[*k256.Point, *k256.Scalar]]()
	for id := range quorum.Iter() {
		if id == corruptedID {
			corruptedSigsMap.Put(id, corruptedPsig)
		} else {
			psig, _ := partialSigs.Get(id)
			corruptedSigsMap.Put(id, psig)
		}
	}
	corruptedSigs := corruptedSigsMap.Freeze()

	// Try to aggregate with the corrupted signature - should trigger identifiable abort
	publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
	aggregator, err := signing.NewAggregator(publicMaterial, scheme)
	require.NoError(t, err)

	// This should fail and identify the bad signature
	_, err = aggregator.Aggregate(corruptedSigs, message)
	require.Error(t, err)

	// Check that the aggregator detected the bad signature
	// The error may be an ABORT or FAILED error depending on where the issue is caught
	require.True(t,
		strings.Contains(err.Error(), "[ABORT]") || strings.Contains(err.Error(), "[FAILED]"),
		"aggregator should detect bad signature, got error: %v", err)
	t.Logf("✅ Aggregator correctly detected and rejected corrupted signature")
}

// networkParticipant wraps cosigner to implement network.Participant interface
type networkParticipant struct {
	*signing.Cosigner[*k256.Point, *k256.Scalar, bip340.Message]
}

func (np networkParticipant) SharingID() sharing.ID {
	return np.Cosigner.SharingID()
}

// TestLindell22ConcurrentSigning tests signing multiple messages concurrently
func TestLindell22ConcurrentSigning(t *testing.T) {
	t.Parallel()

	threshold := uint(3)
	total := uint(5)
	numMessages := 5

	// Setup
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-concurrent-signing")))
	tape := hagrid.NewTranscript("TestConcurrentSigning")
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	// Run DKG
	shards, err := ltu.DoLindell22DKG(t, parties)
	require.NoError(t, err)

	// Select quorum
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := uint(0); i < threshold; i++ {
		quorumSet.Add(sharing.ID(i))
	}
	quorum := quorumSet.Freeze()

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards.Iter() {
		shardsMap[id] = shard
	}

	variant, err := scheme.Variant()
	require.NoError(t, err)

	// Generate multiple messages
	messages := make([][]byte, numMessages)
	for i := 0; i < numMessages; i++ {
		messages[i] = []byte(string(rune('A' + i)))
	}

	// Sign messages concurrently
	var wg sync.WaitGroup
	results := make(chan struct {
		index int
		sig   *bip340.Signature
		err   error
	}, numMessages)

	for i := 0; i < numMessages; i++ {
		wg.Add(1)
		go func(index int, message []byte) {
			defer wg.Done()

			// Create cosigners for this signing session
			signingSID := network.SID(sha3.Sum256(append([]byte("concurrent-"), byte(index))))
			cosigners := ltu.CreateLindell22Cosigners(
				t,
				signingSID,
				shardsMap,
				quorum,
				variant,
				ltu.NewFiatShamirCompiler,
				tape.Clone(),
				prng,
			)

			// Run protocol
			r1bo, err := ltu.DoLindell22Round1(cosigners)
			if err != nil {
				results <- struct {
					index int
					sig   *bip340.Signature
					err   error
				}{index, nil, err}
				return
			}

			participants := make([]networkParticipant, len(cosigners))
			for j, c := range cosigners {
				participants[j] = networkParticipant{c}
			}
			r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

			r2bo, err := ltu.DoLindell22Round2(cosigners, r2bi)
			if err != nil {
				results <- struct {
					index int
					sig   *bip340.Signature
					err   error
				}{index, nil, err}
				return
			}

			r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

			partialSigs, err := ltu.DoLindell22Round3(cosigners, r3bi, message)
			if err != nil {
				results <- struct {
					index int
					sig   *bip340.Signature
					err   error
				}{index, nil, err}
				return
			}

			// Aggregate
			publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
			aggregator, err := signing.NewAggregator(publicMaterial, scheme)
			if err != nil {
				results <- struct {
					index int
					sig   *bip340.Signature
					err   error
				}{index, nil, err}
				return
			}

			sig, err := aggregator.Aggregate(partialSigs.Freeze(), message)
			results <- struct {
				index int
				sig   *bip340.Signature
				err   error
			}{index, sig, err}
		}(i, messages[i])
	}

	wg.Wait()
	close(results)

	// Collect and verify results
	publicMaterial := shardsMap[0].PublicKeyMaterial()
	verifier, err := scheme.Verifier()
	require.NoError(t, err)

	signatures := make([]*bip340.Signature, numMessages)
	for result := range results {
		require.NoError(t, result.err, "signing message %d failed", result.index)
		require.NotNil(t, result.sig)
		signatures[result.index] = result.sig

		// Verify signature
		err = verifier.Verify(result.sig, publicMaterial.PublicKey(), messages[result.index])
		require.NoError(t, err, "signature verification failed for message %d", result.index)
	}

	t.Logf("✅ Successfully signed %d messages concurrently", numMessages)
}

// TestLindell22DifferentQuorums tests signing with different quorum combinations
func TestLindell22DifferentQuorums(t *testing.T) {
	t.Parallel()

	threshold := uint(3)
	total := uint(5)

	// Setup
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-different-quorums")))
	tape := hagrid.NewTranscript("TestDifferentQuorums")
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	// Run DKG
	shards, err := ltu.DoLindell22DKG(t, parties)
	require.NoError(t, err)

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards.Iter() {
		shardsMap[id] = shard
	}

	variant, err := scheme.Variant()
	require.NoError(t, err)

	// Test different quorum combinations
	quorumCombinations := [][]sharing.ID{
		{0, 1, 2},    // First three
		{2, 3, 4},    // Last three
		{0, 2, 4},    // Even indices
		{1, 3, 4},    // Mixed
		{0, 1, 3, 4}, // Larger than threshold
	}

	message := []byte("Test message for different quorums")

	for i, quorumIDs := range quorumCombinations {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			// Create quorum
			quorumSet := hashset.NewComparable[sharing.ID]()
			for _, id := range quorumIDs {
				quorumSet.Add(id)
			}
			quorum := quorumSet.Freeze()

			// Create cosigners
			signingSID := network.SID(sha3.Sum256(append([]byte("quorum-test-"), byte(i))))
			cosigners := ltu.CreateLindell22Cosigners(
				t,
				signingSID,
				shardsMap,
				quorum,
				variant,
				ltu.NewFiatShamirCompiler,
				tape.Clone(),
				prng,
			)

			// Run protocol
			r1bo, err := ltu.DoLindell22Round1(cosigners)
			require.NoError(t, err)

			participants := make([]networkParticipant, len(cosigners))
			for j, c := range cosigners {
				participants[j] = networkParticipant{c}
			}
			r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

			r2bo, err := ltu.DoLindell22Round2(cosigners, r2bi)
			require.NoError(t, err)

			r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

			partialSigs, err := ltu.DoLindell22Round3(cosigners, r3bi, message)
			require.NoError(t, err)

			// Aggregate
			publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
			aggregator, err := signing.NewAggregator(publicMaterial, scheme)
			require.NoError(t, err)

			sig, err := aggregator.Aggregate(partialSigs.Freeze(), message)
			require.NoError(t, err)

			// Verify
			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(sig, publicMaterial.PublicKey(), message)
			require.NoError(t, err)

			t.Logf("✅ Successfully signed with quorum %v", quorumIDs)
		})
	}
}

// TestLindell22EdgeCases tests edge cases like empty messages, large messages
func TestLindell22EdgeCases(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)

	// Setup
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-edge-cases")))
	tape := hagrid.NewTranscript("TestEdgeCases")
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	// Run DKG
	shards, err := ltu.DoLindell22DKG(t, parties)
	require.NoError(t, err)

	// Select quorum
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := uint(0); i < threshold; i++ {
		quorumSet.Add(sharing.ID(i))
	}
	quorum := quorumSet.Freeze()

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards.Iter() {
		shardsMap[id] = shard
	}

	variant, err := scheme.Variant()
	require.NoError(t, err)

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
	rand.Read(testCases[4].message)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create cosigners
			signingSID := network.SID(sha3.Sum256([]byte("edge-case-" + tc.name)))
			cosigners := ltu.CreateLindell22Cosigners(
				t,
				signingSID,
				shardsMap,
				quorum,
				variant,
				ltu.NewFiatShamirCompiler,
				tape.Clone(),
				prng,
			)

			// Run protocol
			r1bo, err := ltu.DoLindell22Round1(cosigners)
			require.NoError(t, err)

			participants := make([]networkParticipant, len(cosigners))
			for i, c := range cosigners {
				participants[i] = networkParticipant{c}
			}
			r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

			r2bo, err := ltu.DoLindell22Round2(cosigners, r2bi)
			require.NoError(t, err)

			r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

			partialSigs, err := ltu.DoLindell22Round3(cosigners, r3bi, tc.message)
			require.NoError(t, err)

			// Aggregate
			publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
			aggregator, err := signing.NewAggregator(publicMaterial, scheme)
			require.NoError(t, err)

			sig, err := aggregator.Aggregate(partialSigs.Freeze(), tc.message)
			require.NoError(t, err)

			// Verify
			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(sig, publicMaterial.PublicKey(), tc.message)
			require.NoError(t, err)

			t.Logf("✅ Successfully signed %s message", tc.name)
		})
	}
}

// TestLindell22DeterministicSigning tests that signing is deterministic with fixed randomness
func TestLindell22DeterministicSigning(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)

	// Setup with fixed seed
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-deterministic")))
	tape := hagrid.NewTranscript("TestDeterministic")

	// Use a fixed seed for deterministic behavior
	fixedSeed := [64]byte{}
	for i := range fixedSeed {
		fixedSeed[i] = byte(i)
	}
	prng1 := pcg.New(0x123456789ABCDEF0, 0xFEDCBA9876543210)
	prng2 := pcg.New(0x123456789ABCDEF0, 0xFEDCBA9876543210)

	// Create scheme with fixed aux
	aux := [32]byte{}
	for i := range aux {
		aux[i] = byte(i + 100)
	}
	scheme1 := bip340.NewSchemeWithAux(aux)
	scheme2 := bip340.NewSchemeWithAux(aux)

	// Setup DKG (run twice with same inputs)
	runDKGAndSign := func(scheme *bip340.Scheme, prng io.Reader) *bip340.Signature {
		shareholders := sharing.NewOrdinalShareholderSet(total)
		ac, err := shamir.NewAccessStructure(threshold, shareholders)
		require.NoError(t, err)

		parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
		for id := range shareholders.Iter() {
			p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
			require.NoError(t, err)
			parties = append(parties, p)
		}

		// Run DKG
		shards, err := ltu.DoLindell22DKG(t, parties)
		require.NoError(t, err)

		// Select quorum
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := uint(0); i < threshold; i++ {
			quorumSet.Add(sharing.ID(i))
		}
		quorum := quorumSet.Freeze()

		// Convert shards to map
		shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
		for id, shard := range shards.Iter() {
			shardsMap[id] = shard
		}

		variant, err := scheme.Variant()
		require.NoError(t, err)

		// Create cosigners
		signingSID := network.SID(sha3.Sum256([]byte("deterministic-signing")))
		cosigners := ltu.CreateLindell22Cosigners(
			t,
			signingSID,
			shardsMap,
			quorum,
			variant,
			ltu.NewFiatShamirCompiler,
			tape.Clone(),
			prng,
		)

		message := []byte("Deterministic message")

		// Run protocol
		r1bo, err := ltu.DoLindell22Round1(cosigners)
		require.NoError(t, err)

		participants := make([]networkParticipant, len(cosigners))
		for i, c := range cosigners {
			participants[i] = networkParticipant{c}
		}
		r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

		r2bo, err := ltu.DoLindell22Round2(cosigners, r2bi)
		require.NoError(t, err)

		r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

		partialSigs, err := ltu.DoLindell22Round3(cosigners, r3bi, message)
		require.NoError(t, err)

		// Aggregate
		publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
		aggregator, err := signing.NewAggregator(publicMaterial, scheme)
		require.NoError(t, err)

		sig, err := aggregator.Aggregate(partialSigs.Freeze(), message)
		require.NoError(t, err)

		return sig
	}

	// Run twice with same setup
	sig1 := runDKGAndSign(scheme1, prng1)
	sig2 := runDKGAndSign(scheme2, prng2)

	// Signatures should be equal with deterministic randomness
	require.True(t, sig1.Equal(sig2), "signatures should be equal with same randomness")
	t.Log("✅ Deterministic signing produces consistent results")
}

// TestLindell22IdentifiableAbortRounds tests identifiable abort in each round
func TestLindell22IdentifiableAbortRounds(t *testing.T) {
	t.Parallel()

	threshold := uint(3)
	total := uint(5)

	// Setup
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-abort-rounds")))
	tape := hagrid.NewTranscript("TestAbortRounds")
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	// Run DKG
	shards, err := ltu.DoLindell22DKG(t, parties)
	require.NoError(t, err)

	// Select quorum
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := uint(0); i < threshold; i++ {
		quorumSet.Add(sharing.ID(i))
	}
	quorum := quorumSet.Freeze()

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards.Iter() {
		shardsMap[id] = shard
	}

	variant, err := scheme.Variant()
	require.NoError(t, err)

	message := []byte("Test abort detection")

	// Test Round 2 abort - bad commitment opening
	t.Run("round2_bad_opening", func(t *testing.T) {
		signingSID := network.SID(sha3.Sum256([]byte("abort-round2")))
		cosigners := ltu.CreateLindell22Cosigners(
			t,
			signingSID,
			shardsMap,
			quorum,
			variant,
			ltu.NewFiatShamirCompiler,
			tape.Clone(),
			prng,
		)

		// Round 1
		r1bo, err := ltu.DoLindell22Round1(cosigners)
		require.NoError(t, err)

		participants := make([]networkParticipant, len(cosigners))
		for i, c := range cosigners {
			participants[i] = networkParticipant{c}
		}
		r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

		// Round 2
		r2bo, err := ltu.DoLindell22Round2(cosigners, r2bi)
		require.NoError(t, err)

		// Corrupt Round 2 broadcast from participant 1
		corruptedID := sharing.ID(1)
		if r2msg, ok := r2bo[corruptedID]; ok {
			// Corrupt the opening
			r2msg.BigROpening = lindell22.Opening{} // Invalid opening
		}

		// Map to inputs
		r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

		// Round 3 should detect the bad opening
		_, err = ltu.DoLindell22Round3(cosigners, r3bi, message)
		require.Error(t, err)
		require.Contains(t, err.Error(), "[ABORT]")
		t.Logf("✅ Successfully detected bad commitment opening in Round 2")
	})

	// Test Round 3 abort - bad DLog proof
	t.Run("round3_bad_dlog", func(t *testing.T) {
		signingSID := network.SID(sha3.Sum256([]byte("abort-round3")))
		cosigners := ltu.CreateLindell22Cosigners(
			t,
			signingSID,
			shardsMap,
			quorum,
			variant,
			ltu.NewFiatShamirCompiler,
			tape.Clone(),
			prng,
		)

		// Round 1
		r1bo, err := ltu.DoLindell22Round1(cosigners)
		require.NoError(t, err)

		participants := make([]networkParticipant, len(cosigners))
		for i, c := range cosigners {
			participants[i] = networkParticipant{c}
		}
		r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

		// Round 2
		r2bo, err := ltu.DoLindell22Round2(cosigners, r2bi)
		require.NoError(t, err)

		// Corrupt DLog proof from participant 1
		corruptedID := sharing.ID(1)
		if r2msg, ok := r2bo[corruptedID]; ok {
			// Create an invalid DLog proof by using a different statement
			// This simulates a malicious participant sending wrong proof
			r2msg.BigR.X = r2msg.BigR.X.Neg() // Negate the point
		}

		// Map to inputs
		r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

		// Round 3 should detect the bad DLog proof
		_, err = ltu.DoLindell22Round3(cosigners, r3bi, message)
		require.Error(t, err)
		// Error may contain ABORT or VERIFICATION_ERROR
		require.True(t,
			bytes.Contains([]byte(err.Error()), []byte("[ABORT]")) ||
				bytes.Contains([]byte(err.Error()), []byte("[VERIFICATION_ERROR]")),
			"expected abort or verification error, got: %v", err)
		t.Logf("✅ Successfully detected bad DLog proof in Round 3")
	})
}

// TestLindell22BenchmarkPerformance benchmarks the performance of the protocol
func BenchmarkLindell22Signing(b *testing.B) {
	// Setup
	threshold := uint(3)
	total := uint(5)

	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("bench-lindell22")))
	tape := hagrid.NewTranscript("BenchmarkLindell22")
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := bip340.NewScheme(prng)
	require.NoError(b, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(b, err)

	parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(b, err)
		parties = append(parties, p)
	}

	// Run DKG
	t := &testing.T{}
	shards, err := ltu.DoLindell22DKG(t, parties)
	require.NoError(b, err)

	// Select quorum
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := uint(0); i < threshold; i++ {
		quorumSet.Add(sharing.ID(i))
	}
	quorum := quorumSet.Freeze()

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards.Iter() {
		shardsMap[id] = shard
	}

	variant, err := scheme.Variant()
	require.NoError(b, err)

	message := []byte("Benchmark message")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create cosigners
		signingSID := network.SID(sha3.Sum256(append([]byte("bench-sign-"), byte(i))))
		cosigners := ltu.CreateLindell22Cosigners(
			t,
			signingSID,
			shardsMap,
			quorum,
			variant,
			ltu.NewFiatShamirCompiler,
			tape.Clone(),
			prng,
		)

		// Run protocol
		r1bo, _ := ltu.DoLindell22Round1(cosigners)

		participants := make([]networkParticipant, len(cosigners))
		for j, c := range cosigners {
			participants[j] = networkParticipant{c}
		}
		r2bi := ntu.MapBroadcastO2I(b, participants, r1bo)

		r2bo, _ := ltu.DoLindell22Round2(cosigners, r2bi)
		r3bi := ntu.MapBroadcastO2I(b, participants, r2bo)

		partialSigs, _ := ltu.DoLindell22Round3(cosigners, r3bi, message)

		// Aggregate
		publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
		aggregator, _ := signing.NewAggregator(publicMaterial, scheme)
		aggregator.Aggregate(partialSigs.Freeze(), message)
	}
}
