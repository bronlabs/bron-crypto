package signing_test

import (
	"crypto/sha3"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls/boldyreva02"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls/boldyreva02/signing"
	tu "github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls/boldyreva02/testutils"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

// TestBoldyrevaDKGAndSign tests the complete DKG and signing flow
func TestBoldyrevaDKGAndSign(t *testing.T) {
	t.Parallel()

	threshold := uint(3)
	total := uint(5)

	// Use BLS12-381 G1 for short key (public keys in G1, signatures in G2)
	group := bls12381.NewG1()
	curveFamily := &bls12381.FamilyTrait{}

	sid := network.SID(sha3.Sum256([]byte("test-boldyreva-dkg-sign")))
	tape := hagrid.NewTranscript("TestBoldyrevaDKGAndSign")
	prng := pcg.NewRandomised()

	// Setup DKG participants
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar]]()
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(
			sid,
			group,
			id,
			ac,
			tape.Clone(),
			prng,
		)
		require.NoError(t, err)
		parties.Put(id, p)
	}

	// Run DKG using testutils
	shards, err := tu.DoBoldyrevaDKG(t, parties.Values(), true) // true for short key
	require.NoError(t, err)
	require.Equal(t, int(total), shards.Size())

	// Verify all shards have the same public key
	var commonPublicKey *bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
	for id, shard := range shards.Iter() {
		require.NotNil(t, shard.PublicKey(), "shard %d has nil public key", id)

		if commonPublicKey == nil {
			commonPublicKey = shard.PublicKey()
		} else {
			require.True(t, commonPublicKey.Equal(shard.PublicKey()),
				"shard %d has different public key", id)
		}
	}

	// Test threshold signing with a quorum
	t.Run("threshold signing", func(t *testing.T) {
		t.Parallel()
		// Select a quorum (threshold participants)
		quorumSet := hashset.NewComparable[sharing.ID]()
		// Sharing IDs start from 1
		for i := range threshold {
			quorumSet.Add(sharing.ID(i + 1))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners for the quorum
		signingSID := network.SID(sha3.Sum256([]byte("test-signing-session")))
		cosigners := make([]*signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar], 0, threshold)

		for id := range quorum.Iter() {
			shard, ok := shards.Get(id)
			require.True(t, ok)
			cosigner, err := signing.NewShortKeyCosigner(
				signingSID,
				curveFamily,
				shard,
				quorum,
				bls.Basic, // Use basic scheme for simplicity
				tape.Clone(),
			)
			require.NoError(t, err)
			cosigners = append(cosigners, cosigner)
		}

		// Create aggregator for the short key scheme
		publicMaterial := cosigners[0].Shard().PublicMaterial
		aggregator, err := signing.NewShortKeyAggregator(
			curveFamily,
			&publicMaterial,
			bls.Basic, // Same rogue key algorithm as used in cosigners
		)
		require.NoError(t, err)

		// Sign a message
		message := []byte("Hello, threshold BLS!")
		scheme, err := bls.NewShortKeyScheme(curveFamily, bls.Basic)
		require.NoError(t, err)
		signature, err := tu.DoThresholdSign(t, cosigners, scheme, message, aggregator)
		require.NoError(t, err)
		require.NotNil(t, signature)

		// Verify the signature using the common public key
		verifier, err := scheme.Verifier()
		require.NoError(t, err)

		err = verifier.Verify(signature, commonPublicKey, message)
		require.NoError(t, err, "threshold signature verification failed")
	})
}

// TestAllRogueKeyPreventionModes tests all rogue key prevention algorithms for both key variants
func TestAllRogueKeyPreventionModes(t *testing.T) {
	t.Parallel()

	rogueKeyAlgs := []struct {
		name string
		alg  bls.RogueKeyPreventionAlgorithm
	}{
		{"Basic", bls.Basic},
		{"MessageAugmentation", bls.MessageAugmentation},
		{"POP", bls.POP},
	}

	keyVariants := []struct {
		name     string
		shortKey bool
	}{
		{"ShortKey", true},
		{"LongKey", false},
	}

	for _, variant := range keyVariants {
		for _, alg := range rogueKeyAlgs {
			t.Run(variant.name+"_"+alg.name, func(t *testing.T) {
				t.Parallel()
				testThresholdSigningWithAlgorithm(t, variant.shortKey, alg.alg)
			})
		}
	}
}

func testThresholdSigningWithAlgorithm(t *testing.T, shortKey bool, rogueKeyAlg bls.RogueKeyPreventionAlgorithm) {
	t.Helper()

	threshold := uint(3)
	total := uint(5)

	var curveFamily curves.PairingFriendlyFamily[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar] = &bls12381.FamilyTrait{}

	sid := network.SID(sha3.Sum256([]byte(fmt.Sprintf("test-rogue-key-%d", rogueKeyAlg))))
	tape := hagrid.NewTranscript("TestRogueKey")
	prng := pcg.NewRandomised()

	// Setup DKG participants
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	if shortKey {
		group := bls12381.NewG1()
		parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar]]()
		for id := range shareholders.Iter() {
			p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
			require.NoError(t, err)
			parties.Put(id, p)
		}
		shards, err := tu.DoBoldyrevaDKG(t, parties.Values(), true)
		require.NoError(t, err)

		// Select a quorum
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := range threshold {
			quorumSet.Add(sharing.ID(i + 1))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners
		signingSID := network.SID(sha3.Sum256([]byte(fmt.Sprintf("test-signing-%d", rogueKeyAlg))))
		cosigners := make([]*signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar], 0, threshold)
		for id := range quorum.Iter() {
			shard, _ := shards.Get(id)
			cosigner, err := signing.NewShortKeyCosigner(signingSID, curveFamily, shard, quorum, rogueKeyAlg, tape.Clone())
			require.NoError(t, err)
			cosigners = append(cosigners, cosigner)
		}

		// Create aggregator
		publicMaterial := cosigners[0].Shard().PublicMaterial
		aggregator, err := signing.NewShortKeyAggregator(curveFamily, &publicMaterial, rogueKeyAlg)
		require.NoError(t, err)

		// Sign and verify
		message := []byte(fmt.Sprintf("Test message for %d", rogueKeyAlg))
		scheme, err := bls.NewShortKeyScheme(curveFamily, rogueKeyAlg)
		require.NoError(t, err)
		signature, err := tu.DoThresholdSign(t, cosigners, scheme, message, aggregator)
		require.NoError(t, err)
		require.NotNil(t, signature)

		// Verify the signature
		verifier, err := scheme.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(signature, publicMaterial.PublicKey(), message)
		require.NoError(t, err)
	} else {
		group := bls12381.NewG2()
		parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*bls12381.PointG2, *bls12381.Scalar]]()
		for id := range shareholders.Iter() {
			p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
			require.NoError(t, err)
			parties.Put(id, p)
		}
		shards, err := tu.DoBoldyrevaDKG(t, parties.Values(), false)
		require.NoError(t, err)

		// Select a quorum
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := range threshold {
			quorumSet.Add(sharing.ID(i + 1))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners
		signingSID := network.SID(sha3.Sum256([]byte(fmt.Sprintf("test-signing-%d", rogueKeyAlg))))
		cosigners := make([]*signing.Cosigner[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar], 0, threshold)
		for id := range quorum.Iter() {
			shard, _ := shards.Get(id)
			cosigner, err := signing.NewLongKeyCosigner(signingSID, curveFamily, shard, quorum, rogueKeyAlg, tape.Clone())
			require.NoError(t, err)
			cosigners = append(cosigners, cosigner)
		}

		// Create aggregator
		publicMaterial := cosigners[0].Shard().PublicMaterial
		aggregator, err := signing.NewLongKeyAggregator(curveFamily, &publicMaterial, rogueKeyAlg)
		require.NoError(t, err)

		// Sign and verify
		message := []byte(fmt.Sprintf("Test message for %d", rogueKeyAlg))
		scheme, err := bls.NewLongKeyScheme(curveFamily, rogueKeyAlg)
		require.NoError(t, err)
		signature, err := tu.DoThresholdSign(t, cosigners, scheme, message, aggregator)
		require.NoError(t, err)
		require.NotNil(t, signature)

		// Verify the signature
		verifier, err := scheme.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(signature, publicMaterial.PublicKey(), message)
		require.NoError(t, err)
	}
}

// TestPartialSignatureVerification tests individual partial signature verification
func TestPartialSignatureVerification(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)

	// Use BLS12-381 G2 for long key (public keys in G2, signatures in G1)
	group := bls12381.NewG2()
	curveFamily := &bls12381.FamilyTrait{}

	sid := network.SID(sha3.Sum256([]byte("test-partial-sig-verification")))
	tape := hagrid.NewTranscript("TestPartialSignatureVerification")
	prng := pcg.NewRandomised()

	// Setup DKG participants
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := shamir.NewAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*bls12381.PointG2, *bls12381.Scalar]]()
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(
			sid,
			group,
			id,
			ac,
			tape.Clone(),
			prng,
		)
		require.NoError(t, err)
		parties.Put(id, p)
	}

	// Run DKG for long key
	shards, err := tu.DoBoldyrevaDKG(t, parties.Values(), false) // false for long key
	require.NoError(t, err)

	// Create cosigners for all participants
	signingSID := network.SID(sha3.Sum256([]byte("test-partial-sig-session")))
	cosigners := make([]*signing.Cosigner[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar], 0, total)

	allIDs := hashset.NewComparable[sharing.ID]()
	for id := range shareholders.Iter() {
		allIDs.Add(id)
	}
	quorum := allIDs.Freeze()

	for id := range shareholders.Iter() {
		shard, _ := shards.Get(id)
		cosigner, err := signing.NewLongKeyCosigner(
			signingSID,
			curveFamily,
			shard,
			quorum,
			bls.MessageAugmentation, // Test with message augmentation
			tape.Clone(),
		)
		require.NoError(t, err)
		cosigners = append(cosigners, cosigner)
	}

	// Create aggregator for the long key scheme
	publicMaterial := cosigners[0].Shard().PublicMaterial
	aggregator, err := signing.NewLongKeyAggregator(
		curveFamily,
		&publicMaterial,
		bls.MessageAugmentation, // Same rogue key algorithm as used in cosigners
	)
	require.NoError(t, err)

	// Produce partial signatures
	message := []byte("Test partial signatures")
	partialSigs, err := tu.ProducePartialSignatures(cosigners, message)
	require.NoError(t, err)
	require.Len(t, partialSigs, int(total))

	// Verify we can aggregate them to get a valid signature
	// Note: The aggregator will verify the partial signatures internally
	partialSigsMap := hashmap.NewComparable[sharing.ID, *boldyreva02.PartialSignature[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]]()
	for id, psig := range partialSigs {
		partialSigsMap.Put(id, psig)
	}

	aggregatedSig, err := aggregator.Aggregate(partialSigsMap.Freeze(), message)
	require.NoError(t, err)
	require.NotNil(t, aggregatedSig)

	// Verify the aggregated signature
	// When using MessageAugmentation, the final signature should be verifiable with MessageAugmentation scheme
	scheme, err := bls.NewLongKeyScheme(curveFamily, bls.MessageAugmentation)
	require.NoError(t, err)
	verifier, err := scheme.Verifier()
	require.NoError(t, err)

	// The signature should be verifiable with the plain message
	// The verifier will handle the augmentation internally
	err = verifier.Verify(aggregatedSig, publicMaterial.PublicKey(), message)
	require.NoError(t, err, "aggregated signature verification failed")
}

// TestCosignerCreationErrors tests error cases for cosigner creation
func TestCosignerCreationErrors(t *testing.T) {
	t.Parallel()

	// Setup minimal valid parameters
	sid := network.SID(sha3.Sum256([]byte("test-errors")))
	curveFamily := &bls12381.FamilyTrait{}
	tape := hagrid.NewTranscript("TestErrors")
	prng := pcg.NewRandomised()

	// Create a valid shard for testing
	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := shamir.NewAccessStructure(2, shareholders)
	require.NoError(t, err)
	parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar]]()
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties.Put(id, p)
	}
	shards, err := tu.DoBoldyrevaDKG(t, parties.Values(), true)
	require.NoError(t, err)
	shard, _ := shards.Get(sharing.ID(1))

	quorumSet := hashset.NewComparable[sharing.ID]()
	quorumSet.Add(sharing.ID(1))
	quorumSet.Add(sharing.ID(2))
	quorum := quorumSet.Freeze()

	t.Run("NilCurveFamily", func(t *testing.T) {
		t.Parallel()
		_, err := signing.NewShortKeyCosigner(sid, nil, shard, quorum, bls.Basic, tape)
		require.Error(t, err)
		require.Contains(t, err.Error(), "curveFamily")
	})

	t.Run("NilTranscript", func(t *testing.T) {
		t.Parallel()
		_, err := signing.NewShortKeyCosigner(sid, curveFamily, shard, quorum, bls.Basic, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "transcript")
	})

	t.Run("NilShard", func(t *testing.T) {
		t.Parallel()
		_, err := signing.NewShortKeyCosigner(sid, curveFamily, nil, quorum, bls.Basic, tape)
		require.Error(t, err)
		require.Contains(t, err.Error(), "shard")
	})

	t.Run("UnsupportedRogueKeyAlgorithm", func(t *testing.T) {
		t.Parallel()
		_, err := signing.NewShortKeyCosigner(sid, curveFamily, shard, quorum, bls.RogueKeyPreventionAlgorithm(99), tape)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})

	t.Run("UnauthorizedQuorum", func(t *testing.T) {
		t.Parallel()
		// Create a quorum that doesn't meet the threshold
		invalidQuorum := hashset.NewComparable[sharing.ID]()
		invalidQuorum.Add(sharing.ID(1)) // Only 1 member, but threshold is 2
		_, err := signing.NewShortKeyCosigner(sid, curveFamily, shard, invalidQuorum.Freeze(), bls.Basic, tape)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not authorized")
	})
}

// TestProducePartialSignatureErrors tests error cases for producing partial signatures
func TestProducePartialSignatureErrors(t *testing.T) {
	t.Parallel()

	// Setup a valid cosigner
	sid := network.SID(sha3.Sum256([]byte("test-partial-sig-errors")))
	curveFamily := &bls12381.FamilyTrait{}
	tape := hagrid.NewTranscript("TestPartialSigErrors")
	prng := pcg.NewRandomised()

	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := shamir.NewAccessStructure(2, shareholders)
	require.NoError(t, err)

	parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar]]()
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties.Put(id, p)
	}
	shards, err := tu.DoBoldyrevaDKG(t, parties.Values(), true)
	require.NoError(t, err)

	shard, _ := shards.Get(sharing.ID(1))

	quorumSet := hashset.NewComparable[sharing.ID]()
	quorumSet.Add(sharing.ID(1))
	quorumSet.Add(sharing.ID(2))
	quorum := quorumSet.Freeze()

	cosigner, err := signing.NewShortKeyCosigner(sid, curveFamily, shard, quorum, bls.Basic, tape)
	require.NoError(t, err)

	t.Run("EmptyMessage", func(t *testing.T) {
		t.Parallel()
		_, err := cosigner.ProducePartialSignature([]byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "message cannot be empty")
	})

	t.Run("WrongRound", func(t *testing.T) {
		t.Parallel()
		// First produce a signature to advance the round
		_, err := cosigner.ProducePartialSignature([]byte("first message"))
		require.NoError(t, err)

		// Try to produce another signature (should fail as we're now in round 2)
		_, err = cosigner.ProducePartialSignature([]byte("second message"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "round")
	})
}

// TestAggregatorCreationErrors tests error cases for aggregator creation
func TestAggregatorCreationErrors(t *testing.T) {
	t.Parallel()

	// Setup minimal valid parameters
	sid := network.SID(sha3.Sum256([]byte("test-aggregator-errors")))
	curveFamily := &bls12381.FamilyTrait{}
	tape := hagrid.NewTranscript("TestAggregatorErrors")
	prng := pcg.NewRandomised()

	// Create valid public material
	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := shamir.NewAccessStructure(2, shareholders)
	require.NoError(t, err)

	parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar]]()
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties.Put(id, p)
	}
	shards, err := tu.DoBoldyrevaDKG(t, parties.Values(), true)
	require.NoError(t, err)

	shard, ok := shards.Get(sharing.ID(1))
	require.True(t, ok)
	publicMaterial := shard.PublicMaterial

	quorumSet := hashset.NewComparable[sharing.ID]()
	quorumSet.Add(sharing.ID(1))
	quorumSet.Add(sharing.ID(2))

	t.Run("NilCurveFamily", func(t *testing.T) {
		t.Parallel()
		_, err := signing.NewShortKeyAggregator(nil, &publicMaterial, bls.Basic)
		require.Error(t, err)
		require.Contains(t, err.Error(), "curveFamily")
	})

	t.Run("UnsupportedRogueKeyAlgorithm", func(t *testing.T) {
		t.Parallel()
		_, err := signing.NewShortKeyAggregator(curveFamily, &publicMaterial, bls.RogueKeyPreventionAlgorithm(99))
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})

}

// TestAggregationErrors tests error cases during aggregation
func TestAggregationErrors(t *testing.T) {
	t.Parallel()

	// Setup valid components
	sid := network.SID(sha3.Sum256([]byte("test-aggregation-errors")))
	curveFamily := &bls12381.FamilyTrait{}
	tape := hagrid.NewTranscript("TestAggregationErrors")
	prng := pcg.NewRandomised()

	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := shamir.NewAccessStructure(2, shareholders)
	require.NoError(t, err)

	parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar]]()
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties.Put(id, p)
	}
	shards, err := tu.DoBoldyrevaDKG(t, parties.Values(), true)
	require.NoError(t, err)

	// Create cosigners and aggregator
	quorumSet := hashset.NewComparable[sharing.ID]()
	quorumSet.Add(sharing.ID(1))
	quorumSet.Add(sharing.ID(2))
	quorum := quorumSet.Freeze()

	cosigners := make([]*signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar], 0)
	for id := range quorum.Iter() {
		shard, _ := shards.Get(id)
		cosigner, err := signing.NewShortKeyCosigner(sid, curveFamily, shard, quorum, bls.Basic, tape.Clone())
		require.NoError(t, err)
		cosigners = append(cosigners, cosigner)
	}

	publicMaterial := cosigners[0].Shard().PublicMaterial
	aggregator, err := signing.NewShortKeyAggregator(curveFamily, &publicMaterial, bls.Basic)
	require.NoError(t, err)

	t.Run("NilPartialSignatures", func(t *testing.T) {
		t.Parallel()
		_, err := aggregator.Aggregate(nil, []byte("message"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "partialSigs")
	})

	t.Run("EmptyMessage", func(t *testing.T) {
		t.Parallel()
		partialSigsMap := hashmap.NewComparable[sharing.ID, *boldyreva02.PartialSignature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]]()
		_, err := aggregator.Aggregate(partialSigsMap.Freeze(), []byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "message cannot be empty")
	})

	t.Run("MissingPublicKey", func(t *testing.T) {
		t.Parallel()
		// Create a partial signature from a non-existent participant
		message := []byte("test message")
		partialSigs, err := tu.ProducePartialSignatures(cosigners, message)
		require.NoError(t, err)

		// Add a fake signature from a non-existent participant
		partialSigsMap := hashmap.NewComparable[sharing.ID, *boldyreva02.PartialSignature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]]()
		for id, psig := range partialSigs {
			partialSigsMap.Put(id, psig)
		}
		// Add fake participant ID that doesn't exist
		partialSigsMap.Put(sharing.ID(99), partialSigs[sharing.ID(1)])

		_, err = aggregator.Aggregate(partialSigsMap.Freeze(), message)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not authorized")
	})
}

// TestDifferentQuorumConfigurations tests various quorum configurations
func TestDifferentQuorumConfigurations(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		total     uint
		threshold uint
		quorumIDs []sharing.ID
	}{
		{"MinimalQuorum_2of3", 3, 2, []sharing.ID{1, 2}},
		{"ExactThreshold_3of5", 5, 3, []sharing.ID{1, 3, 5}},
		{"OverThreshold_4of5", 5, 3, []sharing.ID{1, 2, 3, 4}},
		{"AllParticipants_5of5", 5, 5, []sharing.ID{1, 2, 3, 4, 5}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sid := network.SID(sha3.Sum256([]byte("test-quorum-" + tc.name)))
			curveFamily := &bls12381.FamilyTrait{}
			tape := hagrid.NewTranscript("TestQuorum")
			prng := pcg.NewRandomised()

			// Setup DKG
			group := bls12381.NewG1()
			shareholders := sharing.NewOrdinalShareholderSet(tc.total)
			ac, err := shamir.NewAccessStructure(tc.threshold, shareholders)
			require.NoError(t, err)

			parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar]]()
			for id := range shareholders.Iter() {
				p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
				require.NoError(t, err)
				parties.Put(id, p)
			}
			shards, err := tu.DoBoldyrevaDKG(t, parties.Values(), true)
			require.NoError(t, err)

			// Create quorum
			quorumSet := hashset.NewComparable[sharing.ID]()
			for _, id := range tc.quorumIDs {
				quorumSet.Add(id)
			}
			quorum := quorumSet.Freeze()

			// Create cosigners for quorum
			cosigners := make([]*signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar], 0)
			for id := range quorum.Iter() {
				shard, ok := shards.Get(id)
				require.True(t, ok)
				cosigner, err := signing.NewShortKeyCosigner(sid, curveFamily, shard, quorum, bls.Basic, tape.Clone())
				require.NoError(t, err)
				cosigners = append(cosigners, cosigner)
			}

			// Create aggregator and sign
			publicMaterial := cosigners[0].Shard().PublicMaterial
			aggregator, err := signing.NewShortKeyAggregator(curveFamily, &publicMaterial, bls.Basic)
			require.NoError(t, err)

			message := []byte("Test quorum " + tc.name)
			scheme, err := bls.NewShortKeyScheme(curveFamily, bls.Basic)
			require.NoError(t, err)
			signature, err := tu.DoThresholdSign(t, cosigners, scheme, message, aggregator)
			require.NoError(t, err)

			// Verify
			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(signature, publicMaterial.PublicKey(), message)
			require.NoError(t, err)
		})
	}
}

// TestCosignerGetters tests the getter methods of Cosigner
func TestCosignerGetters(t *testing.T) {
	t.Parallel()

	// Setup a cosigner
	sid := network.SID(sha3.Sum256([]byte("test-getters")))
	curveFamily := &bls12381.FamilyTrait{}
	tape := hagrid.NewTranscript("TestGetters")
	prng := pcg.NewRandomised()

	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := shamir.NewAccessStructure(2, shareholders)
	require.NoError(t, err)

	parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar]]()
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(sid, group, id, ac, tape.Clone(), prng)
		require.NoError(t, err)
		parties.Put(id, p)
	}
	shards, err := tu.DoBoldyrevaDKG(t, parties.Values(), true)
	require.NoError(t, err)

	shard, _ := shards.Get(sharing.ID(1))

	quorumSet := hashset.NewComparable[sharing.ID]()
	quorumSet.Add(sharing.ID(1))
	quorumSet.Add(sharing.ID(2))
	quorum := quorumSet.Freeze()

	rogueKeyAlg := bls.POP
	cosigner, err := signing.NewShortKeyCosigner(sid, curveFamily, shard, quorum, rogueKeyAlg, tape)
	require.NoError(t, err)

	t.Run("SharingID", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, sharing.ID(1), cosigner.SharingID())
	})

	t.Run("Quorum", func(t *testing.T) {
		t.Parallel()
		q := cosigner.Quorum()
		require.Equal(t, 2, q.Size())
		require.True(t, q.Contains(sharing.ID(1)))
		require.True(t, q.Contains(sharing.ID(2)))
	})

	t.Run("Shard", func(t *testing.T) {
		t.Parallel()
		s := cosigner.Shard()
		require.NotNil(t, s)
		require.Equal(t, shard, s)
	})

	t.Run("Variant", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, bls.ShortKey, cosigner.Variant())
	})

	t.Run("TargetRogueKeyPreventionAlgorithm", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, rogueKeyAlg, cosigner.TargetRogueKeyPreventionAlgorithm())
	})

	t.Run("NilCosigner", func(t *testing.T) {
		t.Parallel()
		var nilCosigner *signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
		require.Nil(t, nilCosigner.Quorum())
		require.Nil(t, nilCosigner.Shard())
	})
}
