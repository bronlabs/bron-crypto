package signing_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22/signing"
	ltu "github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22/testutils"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/bip340"
	vanilla "github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/schnorr"
)

// TestLindell22DKGAndSign tests the complete DKG and signing flow for all variants
func TestLindell22DKGAndSign(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		thresh uint
		total  uint
	}{
		{"MinimalQuorum_2of3", 2, 3},
		{"StandardQuorum_3of5", 3, 5},
		{"LargerQuorum_5of7", 5, 7},
	}

	// Test with BIP340
	t.Run("BIP340", func(t *testing.T) {
		t.Parallel()
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestWithBIP340(t, tc.thresh, tc.total)
			})
		}
	})

	// Test with Vanilla Schnorr
	t.Run("VanillaSchnorr", func(t *testing.T) {
		t.Parallel()
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestWithVanillaSchnorr(t, tc.thresh, tc.total)
			})
		}
	})
}

func runTestWithBIP340(t *testing.T, thresh, total uint) {
	t.Helper()
	// Setup
	group := k256.NewCurve()
	prng := pcg.NewRandomised()

	// Create BIP340 scheme
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	// Setup DKG participants
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}

	// Run DKG using testutils
	shards := ltu.DoLindell22DKG(t, parties)
	require.Len(t, shards, int(total))

	// Test thresh signing with a quorum
	t.Run("threshold_signing", func(t *testing.T) {
		t.Parallel()
		// Select a quorum (thresh participants)
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := range thresh {
			quorumSet.Add(sharing.ID(i + 1))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners using testutils
		variant := scheme.Variant()

		// Convert shards to map for testutils
		shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
		for id, shard := range shards {
			shardsMap[id] = shard
		}

		signingCtxs := session_testutils.MakeRandomContexts(t, quorum, prng)
		cosigners := ltu.CreateLindell22Cosigners(t, signingCtxs, shardsMap, variant, prng)

		// Sign a message using the 3-round protocol
		message := []byte("Hello, Lindell22 with BIP340!")

		// Round 1
		r1bo := ltu.DoLindell22Round1(t, cosigners)

		// Map broadcast outputs to inputs
		participants := slices.Collect(maps.Values(cosigners))
		r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

		// Round 2
		r2bo := ltu.DoLindell22Round2(t, cosigners, r2bi)

		// Map broadcast outputs to inputs
		r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

		// Round 3
		partialSigs := ltu.DoLindell22Round3(t, cosigners, r3bi, message)

		// Verify we got partial signatures from all cosigners
		require.Len(t, partialSigs, len(cosigners))

		// Manual aggregation to test signature validity
		publicMaterial := firstCosigner(cosigners).Shard().PublicKeyMaterial()

		// Verify we have partial signatures with the expected properties
		for psig := range maps.Values(partialSigs) {
			require.NotNil(t, psig)
			require.NotNil(t, psig.Sig.R)
			require.NotNil(t, psig.Sig.S)
			require.NotNil(t, psig.Sig.E)
		}

		// Create aggregator using the public material and scheme
		aggregator, err := signing.NewAggregator(publicMaterial, scheme)
		require.NoError(t, err)

		// Aggregate the partial signatures
		aggregatedSig, err := aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
		require.NoError(t, err)
		require.NotNil(t, aggregatedSig)

		// Verify the aggregated signature
		verifier, err := scheme.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(aggregatedSig, publicMaterial.PublicKey(), message)
		require.NoError(t, err)

		t.Logf("✅ Lindell22 thresh signing works with BIP340! Successfully signed and verified a message using the 3-round protocol.")
	})
}

func runTestWithVanillaSchnorr(t *testing.T, thresh, total uint) {
	t.Helper()
	// Setup
	group := k256.NewCurve()
	prng := pcg.NewRandomised()

	// Create Vanilla Schnorr scheme
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, prng)
	require.NoError(t, err)

	// Setup DKG participants
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}

	// Run DKG using testutils
	shards := ltu.DoLindell22DKG(t, parties)
	require.Len(t, shards, int(total))

	// Test thresh signing with a quorum
	t.Run("threshold_signing", func(t *testing.T) {
		t.Parallel()
		// Select a quorum (thresh participants)
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := range thresh {
			quorumSet.Add(sharing.ID(i + 1))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners using testutils
		variant := scheme.Variant()

		// Convert shards to map for testutils
		shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
		for id, shard := range shards {
			shardsMap[id] = shard
		}

		signingCtxs := session_testutils.MakeRandomContexts(t, quorum, prng)
		cosigners := ltu.CreateLindell22Cosigners(t, signingCtxs, shardsMap, variant, prng)

		// Sign a message using the 3-round protocol
		message := []byte("Hello, Lindell22 with Vanilla Schnorr!")

		// Round 1
		r1bo := ltu.DoLindell22Round1(t, cosigners)

		// Map broadcast outputs to inputs
		participants := slices.Collect(maps.Values(cosigners))
		r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

		// Round 2
		r2bo := ltu.DoLindell22Round2(t, cosigners, r2bi)

		// Map broadcast outputs to inputs
		r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

		// Round 3
		partialSigs := ltu.DoLindell22Round3(t, cosigners, r3bi, message)

		// Verify we got partial signatures from all cosigners
		require.Len(t, partialSigs, len(cosigners))

		// Manual aggregation to test signature validity
		publicMaterial := firstCosigner(cosigners).Shard().PublicKeyMaterial()

		// Verify we have partial signatures with the expected properties
		for psig := range maps.Values(partialSigs) {
			require.NotNil(t, psig)
			require.NotNil(t, psig.Sig.R)
			require.NotNil(t, psig.Sig.S)
			require.NotNil(t, psig.Sig.E)
		}

		// Create aggregator using the public material and scheme
		aggregator, err := signing.NewAggregator(publicMaterial, scheme)
		require.NoError(t, err)

		// Aggregate the partial signatures
		aggregatedSig, err := aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
		require.NoError(t, err)
		require.NotNil(t, aggregatedSig)

		// Verify the aggregated signature
		verifier, err := scheme.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(aggregatedSig, publicMaterial.PublicKey(), message)
		require.NoError(t, err)

		t.Logf("✅ Lindell22 thresh signing works with Vanilla Schnorr! Successfully signed and verified a message using the 3-round protocol.")
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
	t.Helper()
	// Setup
	thresh := uint(3)
	total := uint(5)
	group := k256.NewCurve()
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}

	// Run DKG
	shards := ltu.DoLindell22DKG(t, parties)

	// Create signing session
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := range thresh {
		quorumSet.Add(sharing.ID(i + 1))
	}
	quorum := quorumSet.Freeze()

	variant := scheme.Variant()

	// Convert shards to map for testutils
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards {
		shardsMap[id] = shard
	}

	// Create cosigners
	signingCtxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	cosigners := ltu.CreateLindell22Cosigners(t, signingCtxs, shardsMap, variant, prng)

	message := []byte("Test identifiable abort with BIP340")

	// Run rounds 1 and 2 normally
	r1bo := ltu.DoLindell22Round1(t, cosigners)

	participants := slices.Collect(maps.Values(cosigners))
	r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

	r2bo := ltu.DoLindell22Round2(t, cosigners, r2bi)

	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	// Round 3 - get partial signatures
	partialSigs := ltu.DoLindell22Round3(t, cosigners, r3bi, message)

	// Corrupt one signature
	corruptedID := sharing.ID(1)
	// Get the signature for the corrupted ID and replace it
	validPsig, ok := partialSigs[corruptedID]
	require.True(t, ok)

	corruptedPsig := ltu.CreateCorruptedPartialSignature(t, validPsig)

	// Create a new map with the corrupted signature
	corruptedSigsMap := hashmap.NewComparable[sharing.ID, *lindell22.PartialSignature[*k256.Point, *k256.Scalar]]()
	for id := range quorum.Iter() {
		if id == corruptedID {
			corruptedSigsMap.Put(id, corruptedPsig)
		} else {
			psig := partialSigs[id]
			corruptedSigsMap.Put(id, psig)
		}
	}
	corruptedSigs := corruptedSigsMap.Freeze()

	// Try to aggregate with the corrupted signature - should trigger identifiable abort
	publicMaterial := firstCosigner(cosigners).Shard().PublicKeyMaterial()
	aggregator, err := signing.NewAggregator(publicMaterial, scheme)
	require.NoError(t, err)

	// This should fail and identify the bad signature
	_, err = aggregator.Aggregate(corruptedSigs, message)
	require.Error(t, err)

	// Check that the aggregator detected the bad signature
	culprits := errs.HasTagAll(err, base.IdentifiableAbortPartyIDTag)
	require.NotEmpty(t, culprits)
	require.Contains(t, culprits, corruptedID)
	t.Logf("✅ Aggregator correctly detected and rejected corrupted signature with BIP340")
}

func testIdentifiableAbortWithVanillaSchnorr(t *testing.T) {
	t.Helper()
	// Setup
	thresh := uint(3)
	total := uint(5)
	group := k256.NewCurve()
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := vanilla.NewScheme(group, sha256.New, false, true, nil, prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}

	// Run DKG
	shards := ltu.DoLindell22DKG(t, parties)

	// Create signing session
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := range thresh {
		quorumSet.Add(sharing.ID(i + 1))
	}
	quorum := quorumSet.Freeze()

	variant := scheme.Variant()

	// Convert shards to map for testutils
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards {
		shardsMap[id] = shard
	}

	// Create cosigners
	signingCtxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	cosigners := ltu.CreateLindell22Cosigners(t, signingCtxs, shardsMap, variant, prng)

	message := []byte("Test identifiable abort with Vanilla Schnorr")

	// Run rounds 1 and 2 normally
	r1bo := ltu.DoLindell22Round1(t, cosigners)

	participants := slices.Collect(maps.Values(cosigners))
	r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

	r2bo := ltu.DoLindell22Round2(t, cosigners, r2bi)

	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	// Round 3 - get partial signatures
	partialSigs := ltu.DoLindell22Round3(t, cosigners, r3bi, message)

	// Corrupt one signature
	corruptedID1 := sharing.ID(1)
	corruptedID2 := sharing.ID(2)
	corruptedIDs := []sharing.ID{corruptedID1, corruptedID2}
	// Get the signature for the corrupted ID and replace it
	// Create a new map with the corrupted signature
	corruptedSigsMap := hashmap.NewComparable[sharing.ID, *lindell22.PartialSignature[*k256.Point, *k256.Scalar]]()
	for id := range quorum.Iter() {
		if slices.Contains(corruptedIDs, id) {
			validPsig, ok := partialSigs[id]
			require.True(t, ok)
			corruptedPsig := ltu.CreateCorruptedPartialSignature(t, validPsig)
			corruptedSigsMap.Put(id, corruptedPsig)
		} else {
			psig := partialSigs[id]
			corruptedSigsMap.Put(id, psig)
		}
	}
	corruptedSigs := corruptedSigsMap.Freeze()

	// Try to aggregate with the corrupted signature - should trigger identifiable abort
	publicMaterial := firstCosigner(cosigners).Shard().PublicKeyMaterial()
	aggregator, err := signing.NewAggregator(publicMaterial, scheme)
	require.NoError(t, err)

	// This should fail and identify the bad signature
	_, err = aggregator.Aggregate(corruptedSigs, message)
	require.Error(t, err)

	// Check that the aggregator detected the bad signature
	culprits := errs.HasTagAll(err, base.IdentifiableAbortPartyIDTag)
	require.GreaterOrEqual(t, len(culprits), 2)
	require.Contains(t, culprits, corruptedID1)
	require.Contains(t, culprits, corruptedID2)
	t.Logf("✅ Aggregator correctly detected and rejected corrupted signature with Vanilla Schnorr")
}

// TestLindell22ConcurrentSigning tests signing multiple messages concurrently
func TestLindell22ConcurrentSigning(t *testing.T) {
	t.Parallel()

	t.Run("BIP340", func(t *testing.T) {
		t.Parallel()
		testConcurrentSigningWithScheme(t, func(prng io.Reader) (any, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
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
		testConcurrentSigningWithScheme(t, func(prng io.Reader) (any, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
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

func testConcurrentSigningWithScheme(t *testing.T, createScheme func(io.Reader) (any, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error)) {
	t.Helper()
	thresh := uint(3)
	total := uint(5)
	numMessages := 5

	// Setup
	group := k256.NewCurve()
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, variant, err := createScheme(prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}

	// Run DKG
	shards := ltu.DoLindell22DKG(t, parties)

	// Select quorum
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := range thresh {
		quorumSet.Add(sharing.ID(i + 1))
	}
	quorum := quorumSet.Freeze()

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards {
		shardsMap[id] = shard
	}

	// Generate multiple messages
	messages := make([][]byte, numMessages)
	for i := range numMessages {
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

	for i := range numMessages {
		wg.Add(1)
		go func(index int, message []byte) {
			defer wg.Done()

			// Create cosigners for this signing session
			signingCtxs := session_testutils.MakeRandomContexts(t, quorum, prng)
			cosigners := ltu.CreateLindell22Cosigners(t, signingCtxs, shardsMap, variant, prng)

			// Run protocol
			r1bo := ltu.DoLindell22Round1(t, cosigners)

			participants := slices.Collect(maps.Values(cosigners))
			r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

			r2bo := ltu.DoLindell22Round2(t, cosigners, r2bi)

			r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

			partialSigs := ltu.DoLindell22Round3(t, cosigners, r3bi, message)

			// Aggregate based on scheme type
			publicMaterial := firstCosigner(cosigners).Shard().PublicKeyMaterial()
			var (
				sig *schnorrlike.Signature[*k256.Point, *k256.Scalar]
				err error
			)

			switch s := scheme.(type) {
			case *bip340.Scheme:
				aggregator, err := signing.NewAggregator(publicMaterial, s)
				if err != nil {
					results <- result{index, nil, err}
					return
				}
				sig, err = aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
				assert.NoError(t, err)
			case *vanilla.Scheme[*k256.Point, *k256.Scalar]:
				aggregator, err := signing.NewAggregator(publicMaterial, s)
				if err != nil {
					results <- result{index, nil, err}
					return
				}
				sig, err = aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
				assert.NoError(t, err)
			}

			results <- result{index, sig, err}
		}(i, messages[i])
	}

	wg.Wait()
	close(results)

	// Collect and verify results
	publicMaterial := shardsMap[1].PublicKeyMaterial()

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

	thresh := uint(3)
	total := uint(5)

	// Test different quorum combinations
	quorumCombinations := [][]sharing.ID{
		{1, 2, 3},    // First three
		{3, 4, 5},    // Last three
		{1, 3, 4},    // Mixed
		{1, 2, 3, 4}, // Larger than a thresh
	}

	t.Run("BIP340", func(t *testing.T) {
		t.Parallel()
		for i, quorumIDs := range quorumCombinations {
			t.Run(string(rune('A'+i)), func(t *testing.T) {
				t.Parallel()
				testDifferentQuorumsWithScheme(t, thresh, total, quorumIDs, func(prng io.Reader) (any, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
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
		t.Parallel()
		for i, quorumIDs := range quorumCombinations {
			t.Run(string(rune('A'+i)), func(t *testing.T) {
				t.Parallel()
				testDifferentQuorumsWithScheme(t, thresh, total, quorumIDs, func(prng io.Reader) (any, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
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

func testDifferentQuorumsWithScheme(t *testing.T, thresh, total uint, quorumIDs []sharing.ID, createScheme func(io.Reader) (any, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error)) {
	t.Helper()
	// Setup
	group := k256.NewCurve()
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, variant, err := createScheme(prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}

	// Run DKG
	shards := ltu.DoLindell22DKG(t, parties)

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards {
		shardsMap[id] = shard
	}

	// Create quorum
	quorumSet := hashset.NewComparable[sharing.ID]()
	for _, id := range quorumIDs {
		quorumSet.Add(id)
	}
	quorum := quorumSet.Freeze()

	// Create cosigners
	signingCtxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	cosigners := ltu.CreateLindell22Cosigners(t, signingCtxs, shardsMap, variant, prng)

	message := []byte("Test message for different quorums")

	// Run protocol
	r1bo := ltu.DoLindell22Round1(t, cosigners)

	participants := slices.Collect(maps.Values(cosigners))
	r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

	r2bo := ltu.DoLindell22Round2(t, cosigners, r2bi)

	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	partialSigs := ltu.DoLindell22Round3(t, cosigners, r3bi, message)

	// Aggregate
	publicMaterial := firstCosigner(cosigners).Shard().PublicKeyMaterial()

	var sig *schnorrlike.Signature[*k256.Point, *k256.Scalar]
	switch s := scheme.(type) {
	case *bip340.Scheme:
		aggregator, err := signing.NewAggregator(publicMaterial, s)
		require.NoError(t, err)
		sig, err = aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
		require.NoError(t, err)
	case *vanilla.Scheme[*k256.Point, *k256.Scalar]:
		aggregator, err := signing.NewAggregator(publicMaterial, s)
		require.NoError(t, err)
		sig, err = aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
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
	pcg.NewRandomised().Read(testCases[4].message)

	t.Run("BIP340", func(t *testing.T) {
		t.Parallel()
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				testEdgeCasesWithScheme(t, tc.message, func(prng io.Reader) (any, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
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
		t.Parallel()
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				testEdgeCasesWithScheme(t, tc.message, func(prng io.Reader) (any, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error) {
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

func testEdgeCasesWithScheme(t *testing.T, message []byte, createScheme func(io.Reader) (any, tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, []byte], error)) {
	t.Helper()
	thresh := uint(2)
	total := uint(3)

	// Setup
	group := k256.NewCurve()
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, variant, err := createScheme(prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}

	// Run DKG
	shards := ltu.DoLindell22DKG(t, parties)

	// Select quorum
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := range thresh {
		quorumSet.Add(sharing.ID(i + 1))
	}
	quorum := quorumSet.Freeze()

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards {
		shardsMap[id] = shard
	}

	// Create cosigners
	signingCtxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	cosigners := ltu.CreateLindell22Cosigners(t, signingCtxs, shardsMap, variant, prng)

	// Run protocol
	r1bo := ltu.DoLindell22Round1(t, cosigners)

	participants := slices.Collect(maps.Values(cosigners))
	r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

	r2bo := ltu.DoLindell22Round2(t, cosigners, r2bi)

	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	partialSigs := ltu.DoLindell22Round3(t, cosigners, r3bi, message)

	// Aggregate
	publicMaterial := firstCosigner(cosigners).Shard().PublicKeyMaterial()

	var sig *schnorrlike.Signature[*k256.Point, *k256.Scalar]
	switch s := scheme.(type) {
	case *bip340.Scheme:
		aggregator, err := signing.NewAggregator(publicMaterial, s)
		require.NoError(t, err)
		sig, err = aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
		require.NoError(t, err)
	case *vanilla.Scheme[*k256.Point, *k256.Scalar]:
		aggregator, err := signing.NewAggregator(publicMaterial, s)
		require.NoError(t, err)
		sig, err = aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
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

	thresh := uint(2)
	total := uint(3)

	// Setup with fixed seed
	group := k256.NewCurve()

	// Note: BIP340 is deterministic, vanilla Schnorr is randomised
	// So we only test BIP340 here for deterministic behaviour
	t.Run("BIP340", func(t *testing.T) {
		t.Parallel()
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
			ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
			require.NoError(t, err)
			ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

			parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], total)
			for id := range shareholders.Iter() {
				p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
				require.NoError(t, err)
				parties[id] = p
			}

			// Run DKG
			shards := ltu.DoLindell22DKG(t, parties)

			// Select same quorum
			quorumSet := hashset.NewComparable[sharing.ID]()
			for i := range thresh {
				quorumSet.Add(sharing.ID(i + 1))
			}
			quorum := quorumSet.Freeze()

			// Convert shards to map
			shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
			for id, shard := range shards {
				shardsMap[id] = shard
			}

			// Get variant
			variant := scheme.Variant()

			// Create cosigners
			signingCtxs := session_testutils.MakeRandomContexts(t, quorum, prng)
			cosigners := ltu.CreateLindell22Cosigners(t, signingCtxs, shardsMap, variant, prng)

			// Sign same message
			message := []byte("Deterministic test message")

			// Run protocol
			r1bo := ltu.DoLindell22Round1(t, cosigners)

			participants := slices.Collect(maps.Values(cosigners))
			r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

			r2bo := ltu.DoLindell22Round2(t, cosigners, r2bi)

			r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

			partialSigs := ltu.DoLindell22Round3(t, cosigners, r3bi, message)

			// Aggregate
			publicMaterial := firstCosigner(cosigners).Shard().PublicKeyMaterial()
			aggregator, err := signing.NewAggregator(publicMaterial, scheme)
			require.NoError(t, err)

			sig, err := aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
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

	thresh := uint(2)
	total := uint(3)

	// Setup
	group := k256.NewCurve()
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}

	// Run DKG
	shards := ltu.DoLindell22DKG(t, parties)

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards {
		shardsMap[id] = shard
	}

	variant := scheme.Variant()

	t.Run("BadProofInRound3", func(t *testing.T) {
		t.Parallel()
		// Select quorum
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := range thresh {
			quorumSet.Add(sharing.ID(i + 1))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners
		signingCtxs := session_testutils.MakeRandomContexts(t, quorum, prng)
		cosigners := ltu.CreateLindell22Cosigners(t, signingCtxs, shardsMap, variant, prng)

		message := []byte("Test bad proof")

		// Run rounds 1 and 2 normally
		r1bo := ltu.DoLindell22Round1(t, cosigners)

		participants := slices.Collect(maps.Values(cosigners))
		r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

		r2bo := ltu.DoLindell22Round2(t, cosigners, r2bi)

		// Corrupt one cosigner's round 2 output
		corruptedID := sharing.ID(1)
		corruptedOutput := r2bo[corruptedID]
		// Corrupt the BigR to make the proof invalid
		corruptedOutput.BigR.X = corruptedOutput.BigR.X.Neg()
		r2bo[corruptedID] = corruptedOutput

		r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

		// Round 3 should detect the bad proof.
		_, err = cosigners[sharing.ID(2)].Round3(r3bi[sharing.ID(2)], message)
		require.Error(t, err)
		culprit, ok := errs.HasTag(err, base.IdentifiableAbortPartyIDTag)
		require.True(t, ok)
		require.Equal(t, corruptedID, culprit.(sharing.ID))

		t.Logf("✅ Successfully detected bad DLog proof in Round 3")
	})
}

// BenchmarkLindell22Signing benchmarks the performance of the protocol
func BenchmarkLindell22Signing(b *testing.B) {
	// Setup
	thresh := uint(3)
	total := uint(5)

	group := k256.NewCurve()
	prng := pcg.NewRandomised()

	// Create scheme
	scheme, err := bip340.NewScheme(prng)
	if err != nil {
		b.Fatal(err)
	}

	// Setup DKG
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	if err != nil {
		b.Fatal(err)
	}
	ctxs := session_testutils.MakeRandomContexts(b, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		if err != nil {
			b.Fatal(err)
		}
		parties[id] = p
	}

	// Run DKG
	shards := ltu.DoLindell22DKG(&testing.T{}, parties)

	// Select quorum
	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := range thresh {
		quorumSet.Add(sharing.ID(i + 1))
	}
	quorum := quorumSet.Freeze()

	// Convert shards to map
	shardsMap := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, shard := range shards {
		shardsMap[id] = shard
	}

	variant := scheme.Variant()

	message := []byte("Benchmark message")

	b.ResetTimer()
	for range b.N {
		// Create cosigners
		signingCtxs := session_testutils.MakeRandomContexts(&testing.T{}, quorum, prng)
		cosigners := ltu.CreateLindell22Cosigners(&testing.T{}, signingCtxs, shardsMap, variant, prng)

		// Run protocol
		r1bo := ltu.DoLindell22Round1(&testing.T{}, cosigners)

		participants := slices.Collect(maps.Values(cosigners))
		r2bi := ntu.MapBroadcastO2I(&testing.T{}, participants, r1bo)

		r2bo := ltu.DoLindell22Round2(&testing.T{}, cosigners, r2bi)

		r3bi := ntu.MapBroadcastO2I(&testing.T{}, participants, r2bo)

		partialSigs := ltu.DoLindell22Round3(&testing.T{}, cosigners, r3bi, message)

		// Aggregate
		publicMaterial := firstCosigner(cosigners).Shard().PublicKeyMaterial()
		aggregator, _ := signing.NewAggregator(publicMaterial, scheme)
		aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
	}
}

func firstCosigner(cosigners map[sharing.ID]*signing.Cosigner[*k256.Point, *k256.Scalar, []byte]) *signing.Cosigner[*k256.Point, *k256.Scalar, []byte] {
	ids := slices.Collect(maps.Keys(cosigners))
	slices.Sort(ids)
	return cosigners[ids[0]]
}
