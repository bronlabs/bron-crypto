package signing_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls/boldyreva02"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls/boldyreva02/signing"
	tu "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls/boldyreva02/testutils"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

// TestBoldyrevaDKGAndSign tests the complete DKG and signing flow
func TestBoldyrevaDKGAndSign(t *testing.T) {
	t.Parallel()

	const thresh = 3
	const total = 5

	// Use BLS12-381 G1 for short key (public keys in G1, signatures in G2)
	group := bls12381.NewG1()
	curveFamily := &bls12381.FamilyTrait{}
	prng := pcg.NewRandomised()

	// Setup DKG participants
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)

	parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar])
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(
			ctxs[id],
			group,
			ac,
			fiatshamir.Name,
			prng,
		)
		require.NoError(t, err)
		parties[id] = p
	}

	// Run DKG using testutils
	shards := tu.DoBoldyrevaDKG(t, parties, true) // true for short key
	require.Len(t, shards, total)

	// Verify all shards have the same public key
	var commonPublicKey *bls.PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
	for id, shard := range shards {
		require.NotNil(t, shard.PublicKey(), "shard %d has nil public key", id)

		if commonPublicKey == nil {
			commonPublicKey = shard.PublicKey()
		} else {
			require.True(t, commonPublicKey.Equal(shard.PublicKey()),
				"shard %d has different public key", id)
		}
	}

	// Test thresh signing with a quorum
	t.Run("thresh signing", func(t *testing.T) {
		t.Parallel()
		// Select a quorum (thresh participants)
		quorumSet := hashset.NewComparable[sharing.ID]()
		// Sharing IDs start from 1
		for i := range thresh {
			quorumSet.Add(sharing.ID(i + 1))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners for the quorum
		cosigners := make([]*signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar], 0, thresh)
		for id := range quorum.Iter() {
			shard, ok := shards[id]
			require.True(t, ok)
			dkgCtx, ok := ctxs[id]
			require.True(t, ok)
			signCtx, err := dkgCtx.SubContext(quorum)
			require.NoError(t, err)

			cosigner, err := signing.NewShortKeyCosigner(
				signCtx,
				curveFamily,
				ntu.CBORRoundTrip(t, shard),
				bls.Basic, // Use a basic scheme for simplicity
			)
			require.NoError(t, err)
			cosigners = append(cosigners, cosigner)
		}

		// Create aggregator for the short key scheme
		publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
		aggregator, err := signing.NewShortKeyAggregator(
			curveFamily,
			publicMaterial,
			bls.Basic, // Same rogue key algorithm as used in cosigners
		)
		require.NoError(t, err)

		// Sign a message
		message := []byte("Hello, thresh BLS!")
		scheme, err := bls.NewShortKeyScheme(curveFamily, bls.Basic)
		require.NoError(t, err)
		signature, err := tu.DoThresholdSign(t, cosigners, scheme, message, aggregator)
		require.NoError(t, err)
		require.NotNil(t, signature)

		// Verify the signature using the common public key
		verifier, err := scheme.Verifier()
		require.NoError(t, err)

		err = verifier.Verify(signature, commonPublicKey, message)
		require.NoError(t, err, "thresh signature verification failed")
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

	thresh := uint(3)
	total := uint(5)

	var curveFamily curves.PairingFriendlyFamily[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar] = &bls12381.FamilyTrait{}
	prng := pcg.NewRandomised()

	// Setup DKG participants
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	if shortKey {
		group := bls12381.NewG1()
		parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar], total)
		for id := range shareholders.Iter() {
			p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
			require.NoError(t, err)
			parties[id] = p
		}
		shards := tu.DoBoldyrevaDKG(t, parties, true)

		// Select a quorum
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := range thresh {
			quorumSet.Add(sharing.ID(i + 1))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners
		cosigners := make([]*signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar], 0, thresh)
		for id := range quorum.Iter() {
			shard := shards[id]
			dkgCtx := ctxs[id]
			signCtx, err := dkgCtx.SubContext(quorum)
			require.NoError(t, err)
			cosigner, err := signing.NewShortKeyCosigner(signCtx, curveFamily, shard, rogueKeyAlg)
			require.NoError(t, err)
			cosigners = append(cosigners, cosigner)
		}

		// Create aggregator
		publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
		aggregator, err := signing.NewShortKeyAggregator(curveFamily, publicMaterial, rogueKeyAlg)
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
		parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG2, *bls12381.Scalar], total)
		for id := range shareholders.Iter() {
			p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
			require.NoError(t, err)
			parties[id] = p
		}
		shards := tu.DoBoldyrevaDKG(t, parties, false)

		// Select a quorum
		quorumSet := hashset.NewComparable[sharing.ID]()
		for i := range thresh {
			quorumSet.Add(sharing.ID(i + 1))
		}
		quorum := quorumSet.Freeze()

		// Create cosigners
		cosigners := make([]*signing.Cosigner[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar], 0, thresh)
		for id := range quorum.Iter() {
			shard := shards[id]
			dkgCtx := ctxs[id]
			signCtx, err := dkgCtx.SubContext(quorum)
			require.NoError(t, err)
			cosigner, err := signing.NewLongKeyCosigner(signCtx, curveFamily, shard, rogueKeyAlg)
			require.NoError(t, err)
			cosigners = append(cosigners, cosigner)
		}

		// Create aggregator
		publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
		aggregator, err := signing.NewLongKeyAggregator(curveFamily, publicMaterial, rogueKeyAlg)
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

	const thresh = 2
	const total = 3

	// Use BLS12-381 G2 for long key (public keys in G2, signatures in G1)
	group := bls12381.NewG2()
	curveFamily := &bls12381.FamilyTrait{}
	prng := pcg.NewRandomised()

	// Setup DKG participants
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)

	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG2, *bls12381.Scalar])
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(
			ctxs[id],
			group,
			ac,
			fiatshamir.Name,
			prng,
		)
		require.NoError(t, err)
		parties[id] = p
	}

	// Run DKG for long key
	shards := tu.DoBoldyrevaDKG(t, parties, false) // false for long key

	// Create cosigners for all participants
	cosigners := make([]*signing.Cosigner[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar], 0, total)

	allIDs := hashset.NewComparable[sharing.ID]()
	for id := range shareholders.Iter() {
		allIDs.Add(id)
	}
	quorum := allIDs.Freeze()

	for id := range shareholders.Iter() {
		shard := shards[id]
		dkgCtx := ctxs[id]
		signCtx, err := dkgCtx.SubContext(quorum)
		require.NoError(t, err)
		cosigner, err := signing.NewLongKeyCosigner(
			signCtx,
			curveFamily,
			shard,
			bls.MessageAugmentation, // Test with message augmentation
		)
		require.NoError(t, err)
		cosigners = append(cosigners, cosigner)
	}

	// Create aggregator for the long key scheme
	publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
	aggregator, err := signing.NewLongKeyAggregator(
		curveFamily,
		publicMaterial,
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
	curveFamily := &bls12381.FamilyTrait{}
	prng := pcg.NewRandomised()

	// Create a valid shard for testing
	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar], 3)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}
	shards := tu.DoBoldyrevaDKG(t, parties, true)
	shard := shards[sharing.ID(1)]

	quorumSet := hashset.NewComparable[sharing.ID]()
	quorumSet.Add(sharing.ID(1))
	quorumSet.Add(sharing.ID(2))
	quorum := quorumSet.Freeze()

	t.Run("NilCurveFamily", func(t *testing.T) {
		t.Parallel()
		dkgCtx := ctxs[shard.Share().ID()]
		signCtx, err := dkgCtx.SubContext(quorum)
		require.NoError(t, err)
		_, err = signing.NewShortKeyCosigner(signCtx, nil, shard, bls.Basic)
		require.Error(t, err)
		require.Contains(t, err.Error(), "curveFamily")
	})

	t.Run("NilShard", func(t *testing.T) {
		t.Parallel()
		dkgCtx := ctxs[shard.Share().ID()]
		signCtx, err := dkgCtx.SubContext(quorum)
		require.NoError(t, err)
		_, err = signing.NewShortKeyCosigner(signCtx, curveFamily, nil, bls.Basic)
		require.Error(t, err)
		require.Contains(t, err.Error(), "shard")
	})

	t.Run("UnsupportedRogueKeyAlgorithm", func(t *testing.T) {
		t.Parallel()
		dkgCtx := ctxs[shard.Share().ID()]
		signCtx, err := dkgCtx.SubContext(quorum)
		require.NoError(t, err)
		_, err = signing.NewShortKeyCosigner(signCtx, curveFamily, shard, bls.RogueKeyPreventionAlgorithm(99))
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})

	t.Run("UnauthorizedQuorum", func(t *testing.T) {
		t.Parallel()
		// Create a quorum that doesn't meet the thresh
		invalidQuorum := hashset.NewComparable[sharing.ID]()
		invalidQuorum.Add(sharing.ID(1)) // Only 1 member, but thresh is 2
		dkgCtx := ctxs[shard.Share().ID()]
		signCtx, err := dkgCtx.SubContext(invalidQuorum.Freeze())
		require.NoError(t, err)
		_, err = signing.NewShortKeyCosigner(signCtx, curveFamily, shard, bls.Basic)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not authorized")
	})
}

// TestProducePartialSignatureErrors tests error cases for producing partial signatures
func TestProducePartialSignatureErrors(t *testing.T) {
	t.Parallel()

	// Setup a valid cosigner
	curveFamily := &bls12381.FamilyTrait{}
	prng := pcg.NewRandomised()

	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar], 3)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}
	shards := tu.DoBoldyrevaDKG(t, parties, true)

	shard := shards[sharing.ID(1)]

	quorumSet := hashset.NewComparable[sharing.ID]()
	quorumSet.Add(sharing.ID(1))
	quorumSet.Add(sharing.ID(2))
	quorum := quorumSet.Freeze()

	signCtx, err := ctxs[shard.Share().ID()].SubContext(quorum)
	require.NoError(t, err)
	t.Run("EmptyMessage", func(t *testing.T) {
		t.Parallel()
		cosigner, err := signing.NewShortKeyCosigner(signCtx, curveFamily, shard, bls.Basic)
		require.NoError(t, err)

		_, err = cosigner.ProducePartialSignature([]byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "message cannot be empty")
	})

	t.Run("WrongRound", func(t *testing.T) {
		t.Parallel()
		cosigner, err := signing.NewShortKeyCosigner(signCtx, curveFamily, shard, bls.Basic)
		require.NoError(t, err)

		// First produce a signature to advance the round
		_, err = cosigner.ProducePartialSignature([]byte("first message"))
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
	curveFamily := &bls12381.FamilyTrait{}
	prng := pcg.NewRandomised()

	// Create valid public material
	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar], 3)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}
	shards := tu.DoBoldyrevaDKG(t, parties, true)

	shard, ok := shards[sharing.ID(1)]
	require.True(t, ok)
	publicMaterial := shard.PublicKeyMaterial()

	quorumSet := hashset.NewComparable[sharing.ID]()
	quorumSet.Add(sharing.ID(1))
	quorumSet.Add(sharing.ID(2))

	t.Run("NilCurveFamily", func(t *testing.T) {
		t.Parallel()
		_, err := signing.NewShortKeyAggregator(nil, publicMaterial, bls.Basic)
		require.Error(t, err)
		require.Contains(t, err.Error(), "curveFamily")
	})

	t.Run("UnsupportedRogueKeyAlgorithm", func(t *testing.T) {
		t.Parallel()
		_, err := signing.NewShortKeyAggregator(curveFamily, publicMaterial, bls.RogueKeyPreventionAlgorithm(99))
		require.Error(t, err)
		require.ErrorIs(t, err, signing.ErrInvalidArgument)
	})

}

// TestAggregationErrors tests error cases during aggregation
func TestAggregationErrors(t *testing.T) {
	t.Parallel()

	// Setup valid components
	curveFamily := &bls12381.FamilyTrait{}
	prng := pcg.NewRandomised()
	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar])
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}
	shards := tu.DoBoldyrevaDKG(t, parties, true)

	// Create cosigners and aggregator
	quorumSet := hashset.NewComparable[sharing.ID]()
	quorumSet.Add(sharing.ID(1))
	quorumSet.Add(sharing.ID(2))
	quorum := quorumSet.Freeze()

	cosigners := make([]*signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar], 0)
	for id := range quorum.Iter() {
		shard := shards[id]
		signCtx, err := ctxs[id].SubContext(quorum)
		require.NoError(t, err)
		cosigner, err := signing.NewShortKeyCosigner(signCtx, curveFamily, shard, bls.Basic)
		require.NoError(t, err)
		cosigners = append(cosigners, cosigner)
	}

	publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
	aggregator, err := signing.NewShortKeyAggregator(curveFamily, publicMaterial, bls.Basic)
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
		thresh    uint
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
			curveFamily := &bls12381.FamilyTrait{}
			prng := pcg.NewRandomised()

			// Setup DKG
			group := bls12381.NewG1()
			shareholders := sharing.NewOrdinalShareholderSet(tc.total)
			ac, err := threshold.NewThresholdAccessStructure(tc.thresh, shareholders)
			require.NoError(t, err)

			parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar], tc.total)
			ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
			for id := range shareholders.Iter() {
				p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
				require.NoError(t, err)
				parties[id] = p
			}
			shards := tu.DoBoldyrevaDKG(t, parties, true)

			// Create quorum
			quorumSet := hashset.NewComparable[sharing.ID]()
			for _, id := range tc.quorumIDs {
				quorumSet.Add(id)
			}
			quorum := quorumSet.Freeze()

			// Create cosigners for quorum
			cosigners := make([]*signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar], 0)
			for id := range quorum.Iter() {
				shard, ok := shards[id]
				require.True(t, ok)
				signCtx, err := ctxs[id].SubContext(quorum)
				require.NoError(t, err)
				cosigner, err := signing.NewShortKeyCosigner(signCtx, curveFamily, shard, bls.Basic)
				require.NoError(t, err)
				cosigners = append(cosigners, cosigner)
			}

			// Create aggregator and sign
			publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
			aggregator, err := signing.NewShortKeyAggregator(curveFamily, publicMaterial, bls.Basic)
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
	curveFamily := &bls12381.FamilyTrait{}
	prng := pcg.NewRandomised()

	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar], 3)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}
	shards := tu.DoBoldyrevaDKG(t, parties, true)

	shard := shards[sharing.ID(1)]

	quorumSet := hashset.NewComparable[sharing.ID]()
	quorumSet.Add(sharing.ID(1))
	quorumSet.Add(sharing.ID(2))
	quorum := quorumSet.Freeze()

	rogueKeyAlg := bls.POP
	signCtx, err := ctxs[shard.Share().ID()].SubContext(quorum)
	require.NoError(t, err)
	cosigner, err := signing.NewShortKeyCosigner(signCtx, curveFamily, shard, rogueKeyAlg)
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

// ---------------------------------------------------------------------------
// Identifiable abort tests
// ---------------------------------------------------------------------------

// blsSetup creates a DKG, cosigners, and aggregator for BLS identifiable abort
// tests. Returns the cosigners, aggregator, and DKG contexts.
func blsSetup(t *testing.T, thresh, total uint) (
	cosigners []*signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar],
	aggregator *signing.Aggregator[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar],
	quorumIDs []sharing.ID,
) {
	t.Helper()

	curveFamily := &bls12381.FamilyTrait{}
	group := bls12381.NewG1()
	prng := pcg.NewRandomised()

	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar], total)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}
	shards := tu.DoBoldyrevaDKG(t, parties, true)

	quorumSet := hashset.NewComparable[sharing.ID]()
	for i := range thresh {
		quorumSet.Add(sharing.ID(i + 1))
	}
	quorum := quorumSet.Freeze()
	quorumIDs = quorum.List()

	cosigners = make([]*signing.Cosigner[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar], 0, thresh)
	for id := range quorum.Iter() {
		signCtx, err := ctxs[id].SubContext(quorum)
		require.NoError(t, err)
		c, err := signing.NewShortKeyCosigner(signCtx, curveFamily, shards[id], bls.Basic)
		require.NoError(t, err)
		cosigners = append(cosigners, c)
	}

	publicMaterial := cosigners[0].Shard().PublicKeyMaterial()
	aggregator, err = signing.NewShortKeyAggregator(curveFamily, publicMaterial, bls.Basic)
	require.NoError(t, err)

	return cosigners, aggregator, quorumIDs
}

// TestIdentifiableAbort_OnlyCorruptedSignerIsBlamed corrupts one partial BLS
// signature by adding the G2 generator to the first component. The aggregator
// must detect the corrupted signer during individual verification and blame
// only that party.
func TestIdentifiableAbort_OnlyCorruptedSignerIsBlamed(t *testing.T) {
	t.Parallel()

	cosigners, aggregator, quorumIDs := blsSetup(t, 2, 3)

	message := []byte("identifiable abort BLS test")
	partialSigs, err := tu.ProducePartialSignatures(cosigners, message)
	require.NoError(t, err)

	// Corrupt one signer by adding the G2 generator to their first signature component.
	corruptedID := quorumIDs[0]
	g2 := bls12381.NewG2()
	corruptedSigsMap := hashmap.NewComparable[sharing.ID, *boldyreva02.PartialSignature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]]()
	for id, psig := range partialSigs {
		if id == corruptedID {
			corruptedSigmaI := make([]*bls.Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar], len(psig.SigmaI))
			copy(corruptedSigmaI, psig.SigmaI)
			corruptedValue := psig.SigmaI[0].Value().Op(g2.Generator())
			corruptedSigmaI[0], err = bls.NewSignature(corruptedValue, nil)
			require.NoError(t, err)
			corruptedSigsMap.Put(id, &boldyreva02.PartialSignature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]{
				SigmaI:    corruptedSigmaI,
				SigmaPopI: psig.SigmaPopI,
			})
		} else {
			corruptedSigsMap.Put(id, psig)
		}
	}

	_, err = aggregator.Aggregate(corruptedSigsMap.Freeze(), message)
	require.Error(t, err, "aggregation must fail with a corrupted partial signature")

	culprits := errs.HasTagAll(err, base.IdentifiableAbortPartyIDTag)
	require.NotEmpty(t, culprits, "aggregator must detect the corrupted signer")
	assert.Contains(t, culprits, corruptedID, "corrupted signer must be blamed")
	for _, id := range quorumIDs {
		if id != corruptedID {
			assert.NotContains(t, culprits, id, "honest signer %d must not be blamed", id)
		}
	}
}

// TestIdentifiableAbort_IncorrectShare simulates a signer who followed the
// protocol but whose underlying secret share is wrong. The partial signature
// components are valid BLS signatures — just for the wrong keys. The aggregator
// must detect this during individual verification.
func TestIdentifiableAbort_IncorrectShare(t *testing.T) {
	t.Parallel()

	cosigners, aggregator, quorumIDs := blsSetup(t, 2, 3)

	message := []byte("incorrect share BLS test")
	partialSigs, err := tu.ProducePartialSignatures(cosigners, message)
	require.NoError(t, err)

	// Simulate a wrong share: replace all signature components with signatures
	// from random private keys.
	corruptedID := quorumIDs[0]
	curveFamily := &bls12381.FamilyTrait{}
	g1 := bls12381.NewG1()
	sf := bls12381.NewScalarField()
	scheme, err := bls.NewShortKeyScheme(curveFamily, bls.POP)
	require.NoError(t, err)
	blsDst, err := scheme.CipherSuite().GetDst(bls.Basic, bls.ShortKey)
	require.NoError(t, err)

	corruptedSigsMap := hashmap.NewComparable[sharing.ID, *boldyreva02.PartialSignature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]]()
	for id, psig := range partialSigs {
		if id == corruptedID {
			wrongSigmaI := make([]*bls.Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar], len(psig.SigmaI))
			for i := range wrongSigmaI {
				randomScalar, err := sf.Random(pcg.NewRandomised())
				require.NoError(t, err)
				randomKey, err := bls.NewPrivateKey(g1, randomScalar)
				require.NoError(t, err)
				signer, err := scheme.Signer(randomKey, bls.SignWithCustomDST[*bls12381.PointG1](blsDst))
				require.NoError(t, err)
				wrongSigmaI[i], err = signer.Sign(message)
				require.NoError(t, err)
			}
			corruptedSigsMap.Put(id, &boldyreva02.PartialSignature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]{
				SigmaI:    wrongSigmaI,
				SigmaPopI: psig.SigmaPopI,
			})
		} else {
			corruptedSigsMap.Put(id, psig)
		}
	}

	_, err = aggregator.Aggregate(corruptedSigsMap.Freeze(), message)
	require.Error(t, err, "aggregation must fail when a signer used the wrong share")

	culprits := errs.HasTagAll(err, base.IdentifiableAbortPartyIDTag)
	require.NotEmpty(t, culprits, "aggregator must detect the bad signer")
	assert.Contains(t, culprits, corruptedID, "signer with wrong share must be blamed")
	for _, id := range quorumIDs {
		if id != corruptedID {
			assert.NotContains(t, culprits, id, "honest signer %d must not be blamed", id)
		}
	}
}
