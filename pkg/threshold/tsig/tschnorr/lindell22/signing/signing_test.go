package signing_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/bip340"
	vanilla "github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22/signing"
	ltu "github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22/testutils"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

// TestLindell22DKGAndSign tests the complete DKG and signing flow for all variants
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

	// Test with BIP340
	t.Run("BIP340", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestWithBIP340(t, tc.threshold, tc.total)
			})
		}
	})

	// Test with Vanilla Schnorr
	t.Run("VanillaSchnorr", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestWithVanillaSchnorr(t, tc.threshold, tc.total)
			})
		}
	})
}

func runTestWithBIP340(t *testing.T, threshold, total uint) {
	// Setup
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-lindell22-bip340")))
	tape := hagrid.NewTranscript("TestLindell22BIP340")
	prng := pcg.NewRandomised()

	// Create BIP340 scheme
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	// Setup DKG participants
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	// Run DKG using testutils
	shards, err := ltu.DoLindell22DKG(t, parties)
	require.NoError(t, err)
	require.Equal(t, int(total), shards.Size())

	// Test threshold signing with a quorum
	t.Run("threshold_signing", func(t *testing.T) {
		// Select a quorum (threshold participants)
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := uint(0); i < threshold; i++ {
			quorumSet.Add(sharing.ID(i))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners using testutils
		signingSID := network.SID(sha3.Sum256([]byte("test-signing-session-bip340")))
		variant := scheme.Variant()

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
		message := []byte("Hello, Lindell22 with BIP340!")

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

		// Verify the aggregated signature
		verifier, err := scheme.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(aggregatedSig, publicMaterial.PublicKey(), message)
		require.NoError(t, err)

		t.Logf("✅ Lindell22 threshold signing works with BIP340! Successfully signed and verified a message using the 3-round protocol.")
	})
}

func runTestWithVanillaSchnorr(t *testing.T, threshold, total uint) {
	// Setup
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-lindell22-vanilla")))
	tape := hagrid.NewTranscript("TestLindell22Vanilla")
	prng := pcg.NewRandomised()

	// Create Vanilla Schnorr scheme
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, prng)
	require.NoError(t, err)

	// Setup DKG participants
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	// Run DKG using testutils
	shards, err := ltu.DoLindell22DKG(t, parties)
	require.NoError(t, err)
	require.Equal(t, int(total), shards.Size())

	// Test threshold signing with a quorum
	t.Run("threshold_signing", func(t *testing.T) {
		// Select a quorum (threshold participants)
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := uint(0); i < threshold; i++ {
			quorumSet.Add(sharing.ID(i))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners using testutils
		signingSID := network.SID(sha3.Sum256([]byte("test-signing-session-vanilla")))
		variant := scheme.Variant()

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
		message := []byte("Hello, Lindell22 with Vanilla Schnorr!")

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

		// Verify the aggregated signature
		verifier, err := scheme.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(aggregatedSig, publicMaterial.PublicKey(), message)
		require.NoError(t, err)

		t.Logf("✅ Lindell22 threshold signing works with Vanilla Schnorr! Successfully signed and verified a message using the 3-round protocol.")
	})
}

// TestIdentifiableAbort tests the identifiable abort functionality for all variants
func TestIdentifiableAbort(t *testing.T) {
	t.Parallel()

	t.Run("BIP340", func(t *testing.T) {
		t.Parallel()
		testIdentifiableAbortWithBIP340(t)
	})

	t.Run("VanillaSchnorr", func(t *testing.T) {
		t.Parallel()
		testIdentifiableAbortWithVanillaSchnorr(t)
	})
}

func testIdentifiableAbortWithBIP340(t *testing.T) {
	// Setup
	threshold := uint(3)
	total := uint(5)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-identifiable-abort-bip340")))
	tape := hagrid.NewTranscript("TestIdentifiableAbortBIP340")
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
	signingSID := network.SID(sha3.Sum256([]byte("test-signing-abort-bip340")))
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := uint(0); i < threshold; i++ {
		quorumSet.Add(sharing.ID(i))
	}
	quorum := quorumSet.Freeze()

	variant := scheme.Variant()

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

	message := []byte("Test identifiable abort with BIP340")

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
	require.True(t,
		strings.Contains(err.Error(), "[ABORT]") || strings.Contains(err.Error(), "[FAILED]"),
		"aggregator should detect bad signature, got error: %v", err)
	t.Logf("✅ Aggregator correctly detected and rejected corrupted signature with BIP340")
}

func testIdentifiableAbortWithVanillaSchnorr(t *testing.T) {
	// Setup
	threshold := uint(3)
	total := uint(5)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-identifiable-abort-vanilla")))
	tape := hagrid.NewTranscript("TestIdentifiableAbortVanilla")
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, prng)
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
	signingSID := network.SID(sha3.Sum256([]byte("test-signing-abort-vanilla")))
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := uint(0); i < threshold; i++ {
		quorumSet.Add(sharing.ID(i))
	}
	quorum := quorumSet.Freeze()

	variant := scheme.Variant()

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

	message := []byte("Test identifiable abort with Vanilla Schnorr")

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
	require.True(t,
		strings.Contains(err.Error(), "[ABORT]") || strings.Contains(err.Error(), "[FAILED]"),
		"aggregator should detect bad signature, got error: %v", err)
	t.Logf("✅ Aggregator correctly detected and rejected corrupted signature with Vanilla Schnorr")
}

// networkParticipant wraps cosigner to implement network.Participant interface
type networkParticipant struct {
	*signing.Cosigner[*k256.Point, *k256.Scalar, []byte]
}

func (np networkParticipant) SharingID() sharing.ID {
	return np.Cosigner.SharingID()
}

// TestLindell22ConcurrentSigning tests signing multiple messages concurrently
func TestLindell22ConcurrentSigning(t *testing.T) {
	t.Parallel()

	t.Run("BIP340", func(t *testing.T) {
		t.Parallel()
		testConcurrentSigningWithScheme(t, func(prng io.Reader) (interface{}, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
			scheme, err := bip340.NewScheme(prng)
			if err != nil {
				return nil, nil, err
			}
			variant := scheme.Variant()
			return scheme, variant, nil
		})
	})

	t.Run("VanillaSchnorr", func(t *testing.T) {
		t.Parallel()
		testConcurrentSigningWithScheme(t, func(prng io.Reader) (interface{}, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
			group := k256.NewCurve()
			scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, prng)
			if err != nil {
				return nil, nil, err
			}
			variant := scheme.Variant()
			return scheme, variant, nil
		})
	})
}

func testConcurrentSigningWithScheme(t *testing.T, createScheme func(io.Reader) (interface{}, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error)) {
	threshold := uint(3)
	total := uint(5)
	numMessages := 5

	// Setup
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-concurrent-signing")))
	tape := hagrid.NewTranscript("TestConcurrentSigning")
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, variant, err := createScheme(prng)
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

	// Generate multiple messages
	messages := make([][]byte, numMessages)
	for i := 0; i < numMessages; i++ {
		messages[i] = []byte(string(rune('A' + i)))
	}

	// Sign messages concurrently
	var wg sync.WaitGroup
	type result struct {
		index int
		sig   *schnorrlike.Signature[*k256.Point, *k256.Scalar]
		err   error
	}
	results := make(chan result, numMessages)

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
				results <- result{index, nil, err}
				return
			}

			participants := make([]networkParticipant, len(cosigners))
			for j, c := range cosigners {
				participants[j] = networkParticipant{c}
			}
			r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

			r2bo, err := ltu.DoLindell22Round2(cosigners, r2bi)
			if err != nil {
				results <- result{index, nil, err}
				return
			}

			r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

			partialSigs, err := ltu.DoLindell22Round3(cosigners, r3bi, message)
			if err != nil {
				results <- result{index, nil, err}
				return
			}

			// Aggregate based on scheme type
			publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
			var sig *schnorrlike.Signature[*k256.Point, *k256.Scalar]

			switch s := scheme.(type) {
			case *bip340.Scheme:
				aggregator, err := signing.NewAggregator(publicMaterial, s)
				if err != nil {
					results <- result{index, nil, err}
					return
				}
				sig, err = aggregator.Aggregate(partialSigs.Freeze(), message)
			case *vanilla.Scheme[*k256.Point, *k256.Scalar]:
				aggregator, err := signing.NewAggregator(publicMaterial, s)
				if err != nil {
					results <- result{index, nil, err}
					return
				}
				sig, err = aggregator.Aggregate(partialSigs.Freeze(), message)
			}

			results <- result{index, sig, err}
		}(i, messages[i])
	}

	wg.Wait()
	close(results)

	// Collect and verify results
	publicMaterial := shardsMap[0].PublicKeyMaterial()

	signatures := make([]*schnorrlike.Signature[*k256.Point, *k256.Scalar], numMessages)
	for result := range results {
		require.NoError(t, result.err, "signing message %d failed", result.index)
		require.NotNil(t, result.sig)
		signatures[result.index] = result.sig

		// Verify signature based on scheme type
		switch s := scheme.(type) {
		case *bip340.Scheme:
			verifier, err := s.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(result.sig, publicMaterial.PublicKey(), messages[result.index])
			require.NoError(t, err, "signature verification failed for message %d", result.index)
		case *vanilla.Scheme[*k256.Point, *k256.Scalar]:
			verifier, err := s.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(result.sig, publicMaterial.PublicKey(), messages[result.index])
			require.NoError(t, err, "signature verification failed for message %d", result.index)
		}
	}

	t.Logf("✅ Successfully signed %d messages concurrently", numMessages)
}

// TestLindell22DifferentQuorums tests signing with different quorum combinations
func TestLindell22DifferentQuorums(t *testing.T) {
	t.Parallel()

	threshold := uint(3)
	total := uint(5)

	// Test different quorum combinations
	quorumCombinations := [][]sharing.ID{
		{0, 1, 2},    // First three
		{2, 3, 4},    // Last three
		{0, 2, 4},    // Even indices
		{1, 3, 4},    // Mixed
		{0, 1, 3, 4}, // Larger than threshold
	}

	t.Run("BIP340", func(t *testing.T) {
		for i, quorumIDs := range quorumCombinations {
			t.Run(string(rune('A'+i)), func(t *testing.T) {
				testDifferentQuorumsWithScheme(t, threshold, total, quorumIDs, func(prng io.Reader) (interface{}, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
					scheme, err := bip340.NewScheme(prng)
					if err != nil {
						return nil, nil, err
					}
					variant := scheme.Variant()
					return scheme, variant, nil
				})
			})
		}
	})

	t.Run("VanillaSchnorr", func(t *testing.T) {
		for i, quorumIDs := range quorumCombinations {
			t.Run(string(rune('A'+i)), func(t *testing.T) {
				testDifferentQuorumsWithScheme(t, threshold, total, quorumIDs, func(prng io.Reader) (interface{}, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
					group := k256.NewCurve()
					scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, prng)
					if err != nil {
						return nil, nil, err
					}
					variant := scheme.Variant()
					return scheme, variant, nil
				})
			})
		}
	})
}

func testDifferentQuorumsWithScheme(t *testing.T, threshold, total uint, quorumIDs []sharing.ID, createScheme func(io.Reader) (interface{}, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error)) {
	// Setup
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-different-quorums")))
	tape := hagrid.NewTranscript("TestDifferentQuorums")
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, variant, err := createScheme(prng)
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

	// Create quorum
	quorumSet := hashset.NewComparable[sharing.ID]()
	for _, id := range quorumIDs {
		quorumSet.Add(id)
	}
	quorum := quorumSet.Freeze()

	// Create cosigners
	signingSID := network.SID(sha3.Sum256([]byte("quorum-test")))
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

	message := []byte("Test message for different quorums")

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

	var sig *schnorrlike.Signature[*k256.Point, *k256.Scalar]
	switch s := scheme.(type) {
	case *bip340.Scheme:
		aggregator, err := signing.NewAggregator(publicMaterial, s)
		require.NoError(t, err)
		sig, err = aggregator.Aggregate(partialSigs.Freeze(), message)
		require.NoError(t, err)
	case *vanilla.Scheme[*k256.Point, *k256.Scalar]:
		aggregator, err := signing.NewAggregator(publicMaterial, s)
		require.NoError(t, err)
		sig, err = aggregator.Aggregate(partialSigs.Freeze(), message)
		require.NoError(t, err)
	}

	// Verify
	switch s := scheme.(type) {
	case *bip340.Scheme:
		verifier, err := s.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(sig, publicMaterial.PublicKey(), message)
		require.NoError(t, err)
	case *vanilla.Scheme[*k256.Point, *k256.Scalar]:
		verifier, err := s.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(sig, publicMaterial.PublicKey(), message)
		require.NoError(t, err)
	}

	t.Logf("✅ Successfully signed with quorum %v", quorumIDs)
}

// TestLindell22EdgeCases tests edge cases like empty messages, large messages
func TestLindell22EdgeCases(t *testing.T) {
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
	rand.Read(testCases[4].message)

	t.Run("BIP340", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				testEdgeCasesWithScheme(t, tc.message, func(prng io.Reader) (interface{}, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
					scheme, err := bip340.NewScheme(prng)
					if err != nil {
						return nil, nil, err
					}
					variant := scheme.Variant()
					return scheme, variant, nil
				})
			})
		}
	})

	t.Run("VanillaSchnorr", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				testEdgeCasesWithScheme(t, tc.message, func(prng io.Reader) (interface{}, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
					group := k256.NewCurve()
					scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, prng)
					if err != nil {
						return nil, nil, err
					}
					variant := scheme.Variant()
					return scheme, variant, nil
				})
			})
		}
	})
}

func testEdgeCasesWithScheme(t *testing.T, message []byte, createScheme func(io.Reader) (interface{}, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error)) {
	threshold := uint(2)
	total := uint(3)

	// Setup
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-edge-cases")))
	tape := hagrid.NewTranscript("TestEdgeCases")
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, variant, err := createScheme(prng)
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

	// Create cosigners
	signingSID := network.SID(sha3.Sum256([]byte("edge-case")))
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

	partialSigs, err := ltu.DoLindell22Round3(cosigners, r3bi, message)
	require.NoError(t, err)

	// Aggregate
	publicMaterial := cosigners[0].Shard().PublicKeyMaterial()

	var sig *schnorrlike.Signature[*k256.Point, *k256.Scalar]
	switch s := scheme.(type) {
	case *bip340.Scheme:
		aggregator, err := signing.NewAggregator(publicMaterial, s)
		require.NoError(t, err)
		sig, err = aggregator.Aggregate(partialSigs.Freeze(), message)
		require.NoError(t, err)
	case *vanilla.Scheme[*k256.Point, *k256.Scalar]:
		aggregator, err := signing.NewAggregator(publicMaterial, s)
		require.NoError(t, err)
		sig, err = aggregator.Aggregate(partialSigs.Freeze(), message)
		require.NoError(t, err)
	}

	// Verify
	switch s := scheme.(type) {
	case *bip340.Scheme:
		verifier, err := s.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(sig, publicMaterial.PublicKey(), message)
		require.NoError(t, err)
	case *vanilla.Scheme[*k256.Point, *k256.Scalar]:
		verifier, err := s.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(sig, publicMaterial.PublicKey(), message)
		require.NoError(t, err)
	}

	t.Logf("✅ Successfully signed edge case message")
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

	// Note: BIP340 is deterministic, vanilla Schnorr is randomized
	// So we only test BIP340 here for deterministic behavior
	t.Run("BIP340", func(t *testing.T) {
		// Create two identical PRNGs with same seed
		seed := uint64(12345)
		salt := uint64(67890)
		prng1 := pcg.New(seed, salt)
		prng2 := pcg.New(seed, salt)

		// Create schemes with fixed auxiliary data
		aux := [32]byte{}
		for i := range aux {
			aux[i] = byte(i + 100)
		}
		scheme1 := bip340.NewSchemeWithAux(aux)
		scheme2 := bip340.NewSchemeWithAux(aux)

		// Setup DKG (run twice with same inputs)
		runDKGAndSign := func(scheme *bip340.Scheme, prng io.Reader) *schnorrlike.Signature[*k256.Point, *k256.Scalar] {
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

			// Select same quorum
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

			// Get variant
			variant := scheme.Variant()

			// Create cosigners
			cosigners := ltu.CreateLindell22Cosigners(
				t,
				sid,
				shardsMap,
				quorum,
				variant,
				ltu.NewFiatShamirCompiler,
				tape,
				prng,
			)

			// Sign same message
			message := []byte("Deterministic test message")

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

		// Run twice and compare
		sig1 := runDKGAndSign(scheme1, prng1)
		sig2 := runDKGAndSign(scheme2, prng2)

		// Signatures should be identical
		require.True(t, sig1.R.Equal(sig2.R), "R components should be equal")
		require.True(t, sig1.S.Equal(sig2.S), "S components should be equal")
		require.True(t, sig1.E.Equal(sig2.E), "E components should be equal")

		t.Log("✅ BIP340 signing is deterministic with fixed randomness")
	})
}

// TestLindell22IdentifiableAbortRounds tests identifiable abort in different rounds
func TestLindell22IdentifiableAbortRounds(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)

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

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards.Iter() {
		shardsMap[id] = shard
	}

	variant := scheme.Variant()

	t.Run("BadProofInRound3", func(t *testing.T) {
		// Select quorum
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := uint(0); i < threshold; i++ {
			quorumSet.Add(sharing.ID(i))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners
		signingSID := network.SID(sha3.Sum256([]byte("test-bad-proof")))
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

		message := []byte("Test bad proof")

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

		// Corrupt one cosigner's round 2 output
		corruptedID := sharing.ID(0)
		corruptedOutput := r2bo[corruptedID]
		// Corrupt the BigR to make the proof invalid
		corruptedOutput.BigR.X = corruptedOutput.BigR.X.Neg()
		r2bo[corruptedID] = corruptedOutput

		r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

		// Round 3 should detect the bad proof
		_, err = ltu.DoLindell22Round3(cosigners, r3bi, message)
		require.Error(t, err)
		require.True(t,
			bytes.Contains([]byte(err.Error()), []byte("[ABORT]")) ||
				bytes.Contains([]byte(err.Error()), []byte("[VERIFICATION_ERROR]")),
			"expected abort or verification error, got: %v", err)
		t.Logf("✅ Successfully detected bad DLog proof in Round 3")
	})
}

// BenchmarkLindell22Signing benchmarks the performance of the protocol
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
	if err != nil {
		b.Fatal(err)
	}

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	if err != nil {
		b.Fatal(err)
	}

	parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		if err != nil {
			b.Fatal(err)
		}
		parties = append(parties, p)
	}

	// Run DKG
	shards, err := ltu.DoLindell22DKG(&testing.T{}, parties)
	if err != nil {
		b.Fatal(err)
	}

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

	variant := scheme.Variant()

	message := []byte("Benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create cosigners
		signingSID := network.SID(sha3.Sum256(append([]byte("bench-"), byte(i))))
		cosigners := ltu.CreateLindell22Cosigners(
			&testing.T{},
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
		r2bi := ntu.MapBroadcastO2I(&testing.T{}, participants, r1bo)

		r2bo, _ := ltu.DoLindell22Round2(cosigners, r2bi)

		r3bi := ntu.MapBroadcastO2I(&testing.T{}, participants, r2bo)

		partialSigs, _ := ltu.DoLindell22Round3(cosigners, r3bi, message)

		// Aggregate
		publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
		aggregator, _ := signing.NewAggregator(publicMaterial, scheme)
		aggregator.Aggregate(partialSigs.Freeze(), message)
	}
}
