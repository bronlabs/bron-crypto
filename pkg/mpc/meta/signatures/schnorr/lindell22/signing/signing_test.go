package signing_test

import (
	"bytes"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gennaro"
	dkgtu "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr/lindell22/keygen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr/lindell22/signing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/boolexpr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/bip340"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func shareholders(ids ...sharing.ID) ds.Set[sharing.ID] {
	return hashset.NewComparable(ids...).Freeze()
}

// doDKG runs the meta Gennaro DKG and converts output to Lindell22 shards.
func doDKG(
	t *testing.T,
	group *k256.Curve,
	ac accessstructures.Monotone,
	ctxs map[sharing.ID]*session.Context,
) map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar] {
	t.Helper()

	participants := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar])
	for id := range ac.Shareholders().Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, pcg.NewRandomised())
		require.NoError(t, err)
		participants[id] = p
	}
	dkgOutputs := dkgtu.DoGennaroDKG(t, participants)

	shards := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
	for id, output := range dkgOutputs {
		shard, err := keygen.NewShard(output)
		require.NoError(t, err)
		shards[id] = shard
	}
	return shards
}

// signAndAggregate runs the Lindell22 signing protocol for the given quorum
// and returns the aggregated signature.
func signAndAggregate(
	t *testing.T,
	shards map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar],
	quorumIDs []sharing.ID,
	message []byte,
) {
	t.Helper()

	prng := pcg.NewRandomised()
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)
	variant := scheme.Variant()

	quorumSet := hashset.NewComparable(quorumIDs...).Freeze()
	signingCtxs := session_testutils.MakeRandomContexts(t, quorumSet, prng)

	runners := make(map[sharing.ID]network.Runner[*lindell22.PartialSignature[*k256.Point, *k256.Scalar]])
	for _, id := range quorumIDs {
		runner, err := signing.NewRunner(signingCtxs[id], shards[id], fiatshamir.Name, variant, message, pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = runner
	}

	partialSignatures := ntu.TestExecuteRunners(t, runners)
	require.Len(t, partialSignatures, len(quorumIDs))

	anyID := quorumIDs[0]
	aggregator, err := signing.NewAggregator(shards[anyID].PublicKeyMaterial(), scheme)
	require.NoError(t, err)

	sig, err := aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSignatures).Freeze(), message)
	require.NoError(t, err)
	require.NotNil(t, sig)

	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(sig, shards[anyID].PublicKey(), message)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// access-structure fixtures
// ---------------------------------------------------------------------------

type acFixture struct {
	name         string
	ac           accessstructures.Monotone
	qualified    [][]sharing.ID
	unqualified  [][]sharing.ID
	shareholders []sharing.ID
}

func thresholdFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders(1, 2, 3))
	require.NoError(t, err)
	return acFixture{
		name:         "threshold(2,3)",
		ac:           ac,
		qualified:    [][]sharing.ID{{1, 2}, {1, 3}, {2, 3}},
		unqualified:  [][]sharing.ID{{1}, {2}, {3}},
		shareholders: []sharing.ID{1, 2, 3},
	}
}

func unanimityFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := unanimity.NewUnanimityAccessStructure(shareholders(1, 2, 3))
	require.NoError(t, err)
	return acFixture{
		name:         "unanimity(3)",
		ac:           ac,
		qualified:    [][]sharing.ID{{1, 2, 3}},
		unqualified:  [][]sharing.ID{{1}, {2}, {1, 2}, {1, 3}, {2, 3}},
		shareholders: []sharing.ID{1, 2, 3},
	}
}

func cnfFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := cnf.NewCNFAccessStructure(
		shareholders(1, 2),
		shareholders(3, 4),
	)
	require.NoError(t, err)
	return acFixture{
		name:         "cnf({1,2},{3,4})",
		ac:           ac,
		qualified:    [][]sharing.ID{{1, 3}, {1, 4}, {2, 3}, {2, 4}, {1, 2, 3, 4}},
		unqualified:  [][]sharing.ID{{1, 2}, {3, 4}},
		shareholders: []sharing.ID{1, 2, 3, 4},
	}
}

func largeThresholdFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := threshold.NewThresholdAccessStructure(4, shareholders(1, 2, 3, 4, 5, 6, 7))
	require.NoError(t, err)
	return acFixture{
		name:         "threshold(4,7)",
		ac:           ac,
		qualified:    [][]sharing.ID{{1, 2, 3, 4}, {3, 4, 5, 6}, {1, 4, 6, 7}},
		unqualified:  [][]sharing.ID{{1, 2, 3}, {5, 6, 7}},
		shareholders: []sharing.ID{1, 2, 3, 4, 5, 6, 7},
	}
}

// boolexprFixture builds AND(Threshold(2, {1,2,3}), OR(4,5)):
// qualified iff at least 2 of {1,2,3} present AND at least one of {4,5} present.
func boolexprFixture(t *testing.T) acFixture {
	t.Helper()
	tree := boolexpr.And(
		boolexpr.Threshold(2, boolexpr.ID(1), boolexpr.ID(2), boolexpr.ID(3)),
		boolexpr.Or(boolexpr.ID(4), boolexpr.ID(5)),
	)
	ac, err := boolexpr.NewThresholdGateAccessStructure(tree)
	require.NoError(t, err)
	return acFixture{
		name: "boolexpr(2of3 AND 1of2)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 4}, {1, 3, 5}, {2, 3, 4}, {1, 2, 3, 4, 5},
		},
		unqualified: [][]sharing.ID{
			{1, 4}, {4, 5}, {1, 2, 3}, {3, 5},
		},
		shareholders: []sharing.ID{1, 2, 3, 4, 5},
	}
}

func hierarchicalFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
		hierarchical.WithLevel(1, 1, 2),
		hierarchical.WithLevel(2, 3, 4),
	)
	require.NoError(t, err)
	return acFixture{
		name:         "hierarchical(1,2)",
		ac:           ac,
		qualified:    [][]sharing.ID{{1, 3, 4}, {2, 3, 4}, {1, 2, 3, 4}},
		unqualified:  [][]sharing.ID{{3, 4}},
		shareholders: []sharing.ID{1, 2, 3, 4},
	}
}

func allFixtures(t *testing.T) []acFixture {
	t.Helper()
	return []acFixture{
		thresholdFixture(t),
		unanimityFixture(t),
		cnfFixture(t),
		largeThresholdFixture(t),
		boolexprFixture(t),
		hierarchicalFixture(t),
	}
}

// ---------------------------------------------------------------------------
// Signing happy-path: DKG + sign + aggregate + verify across access structures
// ---------------------------------------------------------------------------

func TestSigning_HappyPath(t *testing.T) {
	t.Parallel()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()

			group := k256.NewCurve()
			prng := pcg.NewRandomised()
			ctxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
			shards := doDKG(t, group, fx.ac, ctxs)
			require.Len(t, shards, len(fx.shareholders))

			message := []byte("test message for " + fx.name)

			for _, quorum := range fx.qualified {
				t.Run(formatIDs(quorum), func(t *testing.T) {
					t.Parallel()
					signAndAggregate(t, shards, quorum, message)
				})
			}
		})
	}
}

// TestSigning_UnqualifiedQuorumRejected verifies that creating a signing session
// with an unqualified set of shareholders (size >= 2) is rejected by the MSP
// authorization check in the cosigner.
func TestSigning_UnqualifiedQuorumRejected(t *testing.T) {
	t.Parallel()

	for _, fx := range allFixtures(t) {
		// Filter to multi-party unqualified sets (size >= 2).
		var multiPartyUnqualified [][]sharing.ID
		for _, u := range fx.unqualified {
			if len(u) >= 2 {
				multiPartyUnqualified = append(multiPartyUnqualified, u)
			}
		}
		if len(multiPartyUnqualified) == 0 {
			continue
		}

		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()

			group := k256.NewCurve()
			prng := pcg.NewRandomised()
			ctxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
			shards := doDKG(t, group, fx.ac, ctxs)

			scheme, err := bip340.NewScheme(pcg.NewRandomised())
			require.NoError(t, err)
			variant := scheme.Variant()

			for _, unqualified := range multiPartyUnqualified {
				t.Run(formatIDs(unqualified), func(t *testing.T) {
					t.Parallel()

					quorumSet := hashset.NewComparable(unqualified...).Freeze()
					signingCtxs := session_testutils.MakeRandomContexts(t, quorumSet, pcg.NewRandomised())

					for _, id := range unqualified {
						_, err := signing.NewCosigner(
							signingCtxs[id], shards[id], fiatshamir.Name, variant, pcg.NewRandomised(),
						)
						// The MSP must reject an unqualified quorum.
						require.Error(t, err, "cosigner creation should fail for unqualified quorum %v, party %d", unqualified, id)
						return // one rejection is enough to confirm
					}
				})
			}
		})
	}
}

// TestSigning_MultipleMessages verifies that distinct messages under the same
// key yield distinct valid signatures.
func TestSigning_MultipleMessages(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	fx := thresholdFixture(t)
	ctxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
	shards := doDKG(t, group, fx.ac, ctxs)

	messages := [][]byte{
		[]byte("message one"),
		[]byte("message two"),
		[]byte("message three"),
	}
	quorum := fx.qualified[0]

	for _, msg := range messages {
		t.Run(string(msg), func(t *testing.T) {
			t.Parallel()
			signAndAggregate(t, shards, quorum, msg)
		})
	}
}

// TestSigning_DifferentQualifiedSubsets verifies that different qualified subsets
// produce valid signatures for the same public key (signatures differ due to
// nonce randomness but all verify).
func TestSigning_DifferentQualifiedSubsets(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	fx := thresholdFixture(t)
	ctxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
	shards := doDKG(t, group, fx.ac, ctxs)

	message := []byte("same message, different quorums")

	for _, quorum := range fx.qualified {
		t.Run(formatIDs(quorum), func(t *testing.T) {
			t.Parallel()
			signAndAggregate(t, shards, quorum, message)
		})
	}
}

// TestSigning_TranscriptConsistency verifies all parties derive the same
// transcript state after a signing session.
func TestSigning_TranscriptConsistency(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	fx := thresholdFixture(t)
	ctxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
	shards := doDKG(t, group, fx.ac, ctxs)

	scheme, err := bip340.NewScheme(pcg.NewRandomised())
	require.NoError(t, err)
	variant := scheme.Variant()
	message := []byte("transcript consistency")
	quorum := fx.qualified[0]

	quorumSet := hashset.NewComparable(quorum...).Freeze()
	signingCtxs := session_testutils.MakeRandomContexts(t, quorumSet, pcg.NewRandomised())

	runners := make(map[sharing.ID]network.Runner[*lindell22.PartialSignature[*k256.Point, *k256.Scalar]])
	for _, id := range quorum {
		runner, err := signing.NewRunner(signingCtxs[id], shards[id], fiatshamir.Name, variant, message, pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = runner
	}

	ntu.TestExecuteRunners(t, runners)

	// All parties' transcripts must be identical.
	firstTape, err := signingCtxs[quorum[0]].Transcript().ExtractBytes("test", 32)
	require.NoError(t, err)
	for _, id := range quorum[1:] {
		tape, err := signingCtxs[id].Transcript().ExtractBytes("test", 32)
		require.NoError(t, err)
		require.True(t, bytes.Equal(firstTape, tape),
			"transcript mismatch between party %d and %d", quorum[0], id)
	}
}

// TestSigning_PublicKeysConsistentAcrossShards verifies that all shards agree
// on the aggregate public key.
func TestSigning_PublicKeysConsistentAcrossShards(t *testing.T) {
	t.Parallel()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()

			group := k256.NewCurve()
			prng := pcg.NewRandomised()
			ctxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
			shards := doDKG(t, group, fx.ac, ctxs)

			var refPK *k256.Point
			for id, shard := range shards {
				pk := shard.PublicKey().Value()
				if refPK == nil {
					refPK = pk
				} else {
					require.True(t, refPK.Equal(pk),
						"public key mismatch at shareholder %d", id)
				}
			}
		})
	}
}

// TestSigning_RunnerEndToEnd exercises the full runner-based flow (DKG → sign →
// aggregate → verify) for each access structure, matching the meta DKG runner
// test pattern.
func TestSigning_RunnerEndToEnd(t *testing.T) {
	t.Parallel()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()

			group := k256.NewCurve()
			prng := pcg.NewRandomised()
			scheme, err := bip340.NewScheme(prng)
			require.NoError(t, err)

			// DKG via runners
			dkgCtxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
			dkgRunners := dkgtu.MakeGennaroDKGRunners(t, dkgCtxs, fx.ac, fiatshamir.Name, group)
			dkgOutputs := ntu.TestExecuteRunners(t, dkgRunners)
			require.Len(t, dkgOutputs, len(fx.shareholders))

			shards := make(map[sharing.ID]*lindell22.Shard[*k256.Point, *k256.Scalar])
			for id, output := range dkgOutputs {
				shard, err := keygen.NewShard(output)
				require.NoError(t, err)
				shards[id] = shard
			}

			message := []byte("runner end-to-end test")
			quorum := fx.qualified[0]
			quorumSet := hashset.NewComparable(quorum...).Freeze()
			signingCtxs := session_testutils.MakeRandomContexts(t, quorumSet, prng)

			variant := scheme.Variant()
			runners := make(map[sharing.ID]network.Runner[*lindell22.PartialSignature[*k256.Point, *k256.Scalar]])
			for _, id := range quorum {
				runner, err := signing.NewRunner(signingCtxs[id], shards[id], fiatshamir.Name, variant, message, pcg.NewRandomised())
				require.NoError(t, err)
				runners[id] = runner
			}

			partialSigs := ntu.TestExecuteRunners(t, runners)
			require.Len(t, partialSigs, len(quorum))

			aggregator, err := signing.NewAggregator(shards[quorum[0]].PublicKeyMaterial(), scheme)
			require.NoError(t, err)

			sig, err := aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSigs).Freeze(), message)
			require.NoError(t, err)
			require.NotNil(t, sig)

			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			require.NoError(t, verifier.Verify(sig, shards[quorum[0]].PublicKey(), message))
		})
	}
}

// TestSigning_ShardCBORRoundTrip verifies that shards survive CBOR serialisation.
func TestSigning_ShardCBORRoundTrip(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	fx := thresholdFixture(t)
	ctxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
	shards := doDKG(t, group, fx.ac, ctxs)

	for id, shard := range shards {
		roundTripped := ntu.CBORRoundTrip(t, shard)
		require.True(t, shard.PublicKey().Value().Equal(roundTripped.PublicKey().Value()),
			"public key mismatch after CBOR round-trip for shareholder %d", id)
	}
}

// ---------------------------------------------------------------------------
// Identifiable abort: only the corrupted signer must be blamed
// ---------------------------------------------------------------------------

// TestIdentifiableAbort_OnlyCorruptedSignerIsBlamed runs a full signing
// protocol, corrupts one partial signature, and verifies that the aggregator's
// identification phase pins blame exclusively on the corrupted signer.
// Honest signers must NOT appear in the culprit list.
func TestIdentifiableAbort_OnlyCorruptedSignerIsBlamed(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	fx := thresholdFixture(t) // threshold(2,3)
	ctxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
	shards := doDKG(t, group, fx.ac, ctxs)

	quorum := fx.qualified[0] // e.g. {1, 2}
	quorumSet := hashset.NewComparable(quorum...).Freeze()
	signingCtxs := session_testutils.MakeRandomContexts(t, quorumSet, prng)

	variant := scheme.Variant()
	cosigners := make(map[sharing.ID]*signing.Cosigner[*k256.Point, *k256.Scalar, []byte])
	for _, id := range quorum {
		cosigner, err := signing.NewCosigner(signingCtxs[id], shards[id], fiatshamir.Name, variant, pcg.NewRandomised())
		require.NoError(t, err)
		cosigners[id] = cosigner
	}
	r1bo := make(map[sharing.ID]*signing.Round1Broadcast[*k256.Point, *k256.Scalar, []byte])
	r1uo := make(map[sharing.ID]network.RoundMessages[*signing.Round1P2P[*k256.Point, *k256.Scalar, []byte], *signing.Cosigner[*k256.Point, *k256.Scalar, []byte]])
	for id, c := range cosigners {
		bOut, uOut, err := c.Round1()
		require.NoError(t, err)
		r1bo[id] = bOut
		r1uo[id] = uOut
	}
	participants := slices.Collect(maps.Values(cosigners))
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)

	r2bo := make(map[sharing.ID]*signing.Round2Broadcast[*k256.Point, *k256.Scalar, []byte])
	for id, c := range cosigners {
		out, err := c.Round2(r2bi[id], r2ui[id])
		require.NoError(t, err)
		r2bo[id] = out
	}
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	partialSigs := make(map[sharing.ID]*lindell22.PartialSignature[*k256.Point, *k256.Scalar])
	for id, c := range cosigners {
		psig, err := c.Round3(r3bi[id], []byte("identifiable abort"))
		require.NoError(t, err)
		partialSigs[id] = psig
	}
	require.Len(t, partialSigs, len(quorum))

	// Corrupt exactly one signer by adding 1 to its S value.
	corruptedID := quorum[0]
	sf := k256.NewScalarField()
	corruptedSigsMap := hashmap.NewComparable[sharing.ID, *lindell22.PartialSignature[*k256.Point, *k256.Scalar]]()
	for _, id := range quorum {
		psig := partialSigs[id]
		if id == corruptedID {
			corruptedSigsMap.Put(id, &lindell22.PartialSignature[*k256.Point, *k256.Scalar]{
				Sig: schnorrlike.Signature[*k256.Point, *k256.Scalar]{
					E: psig.Sig.E,
					R: psig.Sig.R,
					S: psig.Sig.S.Add(sf.One()),
				},
			})
		} else {
			corruptedSigsMap.Put(id, psig)
		}
	}

	aggregator, err := signing.NewCosigningAggregator(cosigners[quorum[0]], shards[quorum[0]].PublicKeyMaterial(), scheme)
	require.NoError(t, err)

	_, err = aggregator.Aggregate(corruptedSigsMap.Freeze(), []byte("identifiable abort"))
	require.Error(t, err, "aggregation must fail with a corrupted partial signature")

	culprits := errs.HasTagAll(err, base.IdentifiableAbortPartyIDTag)
	require.NotEmpty(t, culprits, "identification phase must detect at least one culprit")

	// The corrupted signer must be blamed.
	assert.Contains(t, culprits, corruptedID, "corrupted signer must be among the culprits")
	// Honest signers must NOT be blamed.
	for _, id := range quorum {
		if id != corruptedID {
			assert.NotContains(t, culprits, id, "honest signer %d must not be blamed", id)
		}
	}
}

// TestIdentifiableAbort_IncorrectShare simulates a signer who follows the
// protocol honestly but whose underlying secret share is wrong (e.g. corrupted
// DKG output). The partial signature is structurally valid — computed as
// s = wrong_d' * e + k — but uses an incorrect share. The ZeroPublicKeyShift
// is honest. The aggregator must detect this signer during identification.
func TestIdentifiableAbort_IncorrectShare(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)
	sf := k256.NewScalarField()

	fx := thresholdFixture(t)
	ctxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
	shards := doDKG(t, group, fx.ac, ctxs)

	message := []byte("incorrect share test")
	quorum := fx.qualified[0]
	quorumSet := hashset.NewComparable(quorum...).Freeze()
	signingCtxs := session_testutils.MakeRandomContexts(t, quorumSet, prng)

	variant := scheme.Variant()
	cosigners := make(map[sharing.ID]*signing.Cosigner[*k256.Point, *k256.Scalar, []byte])
	for _, id := range quorum {
		cosigner, err := signing.NewCosigner(signingCtxs[id], shards[id], fiatshamir.Name, variant, pcg.NewRandomised())
		require.NoError(t, err)
		cosigners[id] = cosigner
	}
	r1bo := make(map[sharing.ID]*signing.Round1Broadcast[*k256.Point, *k256.Scalar, []byte])
	r1uo := make(map[sharing.ID]network.RoundMessages[*signing.Round1P2P[*k256.Point, *k256.Scalar, []byte], *signing.Cosigner[*k256.Point, *k256.Scalar, []byte]])
	for id, c := range cosigners {
		bOut, uOut, err := c.Round1()
		require.NoError(t, err)
		r1bo[id] = bOut
		r1uo[id] = uOut
	}
	participants := slices.Collect(maps.Values(cosigners))
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)

	r2bo := make(map[sharing.ID]*signing.Round2Broadcast[*k256.Point, *k256.Scalar, []byte])
	for id, c := range cosigners {
		out, err := c.Round2(r2bi[id], r2ui[id])
		require.NoError(t, err)
		r2bo[id] = out
	}
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	partialSigs := make(map[sharing.ID]*lindell22.PartialSignature[*k256.Point, *k256.Scalar])
	for id, c := range cosigners {
		psig, err := c.Round3(r3bi[id], message)
		require.NoError(t, err)
		partialSigs[id] = psig
	}

	// Simulate a signer whose share is off by delta. A partial signature
	// computed with share (d_i' + δ) instead of d_i' satisfies:
	//   s_bad = (d_i' + δ)·e + k = s_good + δ·e
	// The ZeroPublicKeyShift is left unchanged (honest zero-share computation).
	corruptedID := quorum[0]
	delta := sf.FromUint64(7)
	corruptedSigsMap := hashmap.NewComparable[sharing.ID, *lindell22.PartialSignature[*k256.Point, *k256.Scalar]]()
	for _, id := range quorum {
		psig := partialSigs[id]
		if id == corruptedID {
			corruptedSigsMap.Put(id, &lindell22.PartialSignature[*k256.Point, *k256.Scalar]{
				Sig: schnorrlike.Signature[*k256.Point, *k256.Scalar]{
					E: psig.Sig.E,
					R: psig.Sig.R,
					S: psig.Sig.S.Add(delta.Mul(psig.Sig.E)),
				},
			})
		} else {
			corruptedSigsMap.Put(id, psig)
		}
	}

	aggregator, err := signing.NewCosigningAggregator(cosigners[quorum[0]], shards[quorum[0]].PublicKeyMaterial(), scheme)
	require.NoError(t, err)

	_, err = aggregator.Aggregate(corruptedSigsMap.Freeze(), message)
	require.Error(t, err, "aggregation must fail when one share is incorrect")

	culprits := errs.HasTagAll(err, base.IdentifiableAbortPartyIDTag)
	require.NotEmpty(t, culprits, "identification phase must detect the bad signer")
	assert.Contains(t, culprits, corruptedID, "signer with wrong share must be blamed")
	for _, id := range quorum {
		if id != corruptedID {
			assert.NotContains(t, culprits, id, "honest signer %d must not be blamed", id)
		}
	}
}

// TestIdentifiableAbort_CorruptedR verifies that a cosigning
// aggregator catches a malicious signer who substitutes a different R in their
// partial signature. Given a valid partial signature (e, R_i, s_i) that
// satisfies s_i·G = R_i + e·PK_i, the adversary adds a random δ to both the
// response and the nonce commitment:
//
//	R' = R_i + δ·G,  s' = s_i + δ   →   s'·G = R' + e·PK_i  ✓
//
// The resulting partial signature individually verifies, but the cosigning
// aggregator knows the expected committed R_i from the protocol and can
// attribute blame immediately.
func TestIdentifiableAbort_CorruptedR(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)
	sf := k256.NewScalarField()

	fx := thresholdFixture(t)
	ctxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
	shards := doDKG(t, group, fx.ac, ctxs)

	message := []byte("corrupted R test")
	quorum := fx.qualified[0]
	quorumSet := hashset.NewComparable(quorum...).Freeze()
	variant := scheme.Variant()

	signingCtxs := session_testutils.MakeRandomContexts(t, quorumSet, prng)
	cosigners := make(map[sharing.ID]*signing.Cosigner[*k256.Point, *k256.Scalar, []byte])
	for _, id := range quorum {
		c, err := signing.NewCosigner(signingCtxs[id], shards[id], fiatshamir.Name, variant, pcg.NewRandomised())
		require.NoError(t, err)
		cosigners[id] = c
	}

	r1bo := make(map[sharing.ID]*signing.Round1Broadcast[*k256.Point, *k256.Scalar, []byte])
	r1uo := make(map[sharing.ID]network.RoundMessages[*signing.Round1P2P[*k256.Point, *k256.Scalar, []byte], *signing.Cosigner[*k256.Point, *k256.Scalar, []byte]])
	for id, c := range cosigners {
		bOut, uOut, err := c.Round1()
		require.NoError(t, err)
		r1bo[id] = bOut
		r1uo[id] = uOut
	}
	participants := slices.Collect(maps.Values(cosigners))
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)

	r2bo := make(map[sharing.ID]*signing.Round2Broadcast[*k256.Point, *k256.Scalar, []byte])
	for id, c := range cosigners {
		out, err := c.Round2(r2bi[id], r2ui[id])
		require.NoError(t, err)
		r2bo[id] = out
	}
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	partialSigs := make(map[sharing.ID]*lindell22.PartialSignature[*k256.Point, *k256.Scalar])
	for id, c := range cosigners {
		psig, err := c.Round3(r3bi[id], message)
		require.NoError(t, err)
		partialSigs[id] = psig
	}

	// Corrupt one signer's R: add δ·G to R and δ to S. The resulting partial
	// signature individually verifies but shifts the committed nonce.
	corruptedID := quorum[0]
	delta, err := sf.Random(prng)
	require.NoError(t, err)
	deltaG := group.ScalarBaseOp(delta)

	corruptedSigsMap := hashmap.NewComparable[sharing.ID, *lindell22.PartialSignature[*k256.Point, *k256.Scalar]]()
	for _, id := range quorum {
		psig := partialSigs[id]
		if id == corruptedID {
			corruptedSigsMap.Put(id, &lindell22.PartialSignature[*k256.Point, *k256.Scalar]{
				Sig: schnorrlike.Signature[*k256.Point, *k256.Scalar]{
					E: psig.Sig.E,
					R: psig.Sig.R.Op(deltaG),
					S: psig.Sig.S.Add(delta),
				},
			})
		} else {
			corruptedSigsMap.Put(id, psig)
		}
	}

	aggregator, err := signing.NewCosigningAggregator(cosigners[quorum[1]], shards[quorum[0]].PublicKeyMaterial(), scheme)
	require.NoError(t, err)

	_, err = aggregator.Aggregate(corruptedSigsMap.Freeze(), message)
	require.Error(t, err, "aggregation must fail when R is corrupted")

	culprits := errs.HasTagAll(err, base.IdentifiableAbortPartyIDTag)
	require.NotEmpty(t, culprits, "cosigning aggregator must identify the cheater")
	assert.Contains(t, culprits, corruptedID, "signer who corrupted R must be blamed")
	for _, id := range quorum {
		if id != corruptedID {
			assert.NotContains(t, culprits, id, "honest signer %d must not be blamed", id)
		}
	}
	require.ErrorIs(t, err, base.ErrAbort)
}

// TestIdentifiableAbort_CorruptedR_CosigningAggregator is the same attack as
// CorruptedR_EscapesBlame (δ added to both R and S), but the aggregator is
// also a cosigner and retains each party's committed R from round 2. It
// cross-checks the partial signature R against the expected value and
// identifies the corrupted signer before even reaching signature verification.
func TestIdentifiableAbort_CorruptedR_CosigningAggregator(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)
	sf := k256.NewScalarField()

	fx := thresholdFixture(t)
	dkgCtxs := session_testutils.MakeRandomContexts(t, fx.ac.Shareholders(), prng)
	shards := doDKG(t, group, fx.ac, dkgCtxs)

	message := []byte("cosigning aggregator R test")
	quorum := fx.qualified[0]
	quorumSet := hashset.NewComparable(quorum...).Freeze()
	variant := scheme.Variant()

	// Create cosigners directly so we can pass one to NewCosigningAggregator.
	signingCtxs := session_testutils.MakeRandomContexts(t, quorumSet, prng)
	cosigners := make(map[sharing.ID]*signing.Cosigner[*k256.Point, *k256.Scalar, []byte])
	for _, id := range quorum {
		c, err := signing.NewCosigner(signingCtxs[id], shards[id], fiatshamir.Name, variant, pcg.NewRandomised())
		require.NoError(t, err)
		cosigners[id] = c
	}

	// Round 1
	r1bo := make(map[sharing.ID]*signing.Round1Broadcast[*k256.Point, *k256.Scalar, []byte])
	r1uo := make(map[sharing.ID]network.RoundMessages[*signing.Round1P2P[*k256.Point, *k256.Scalar, []byte], *signing.Cosigner[*k256.Point, *k256.Scalar, []byte]])
	for id, c := range cosigners {
		bOut, uOut, err := c.Round1()
		require.NoError(t, err)
		r1bo[id] = bOut
		r1uo[id] = uOut
	}
	participants := slices.Collect(maps.Values(cosigners))
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)

	// Round 2
	r2bo := make(map[sharing.ID]*signing.Round2Broadcast[*k256.Point, *k256.Scalar, []byte])
	for id, c := range cosigners {
		out, err := c.Round2(r2bi[id], r2ui[id])
		require.NoError(t, err)
		r2bo[id] = out
	}
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	// Round 3
	partialSigs := make(map[sharing.ID]*lindell22.PartialSignature[*k256.Point, *k256.Scalar])
	for id, c := range cosigners {
		psig, err := c.Round3(r3bi[id], message)
		require.NoError(t, err)
		partialSigs[id] = psig
	}

	// Pick one cosigner as the aggregator — it now knows the correct
	// aggregated R and each party's committed R from the protocol.
	aggregatorCosigner := cosigners[quorum[0]]

	// Corrupt a DIFFERENT signer's R: add δ·G to R and δ to S.
	corruptedID := quorum[1]
	delta, err := sf.Random(prng)
	require.NoError(t, err)
	deltaG := group.ScalarBaseOp(delta)

	corruptedSigsMap := hashmap.NewComparable[sharing.ID, *lindell22.PartialSignature[*k256.Point, *k256.Scalar]]()
	for _, id := range quorum {
		psig := partialSigs[id]
		if id == corruptedID {
			corruptedSigsMap.Put(id, &lindell22.PartialSignature[*k256.Point, *k256.Scalar]{
				Sig: schnorrlike.Signature[*k256.Point, *k256.Scalar]{
					E: psig.Sig.E,
					R: psig.Sig.R.Op(deltaG),
					S: psig.Sig.S.Add(delta),
				},
			})
		} else {
			corruptedSigsMap.Put(id, psig)
		}
	}

	aggregator, err := signing.NewCosigningAggregator(aggregatorCosigner, shards[quorum[0]].PublicKeyMaterial(), scheme)
	require.NoError(t, err)

	_, err = aggregator.Aggregate(corruptedSigsMap.Freeze(), message)
	require.Error(t, err, "aggregation must fail when R is corrupted")

	culprits := errs.HasTagAll(err, base.IdentifiableAbortPartyIDTag)
	require.NotEmpty(t, culprits, "cosigning aggregator must identify the cheater")
	assert.Contains(t, culprits, corruptedID, "signer who corrupted R must be blamed")
	for _, id := range quorum {
		if id != corruptedID {
			assert.NotContains(t, culprits, id, "honest signer %d must not be blamed", id)
		}
	}
}

// ---------------------------------------------------------------------------
// formatting helper
// ---------------------------------------------------------------------------

func formatIDs(ids []sharing.ID) string {
	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	s := "{"
	for i, id := range sorted {
		if i > 0 {
			s += ","
		}
		buf := ""
		n := id
		if n == 0 {
			buf = "0"
		}
		for n > 0 {
			buf = string(rune('0'+n%10)) + buf
			n /= 10
		}
		s += buf
	}
	return s + "}"
}
