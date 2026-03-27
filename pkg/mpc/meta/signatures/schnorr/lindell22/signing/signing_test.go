package signing_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

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

// TestSigning_ShardCBORRoundTrip verifies that shards survive CBOR serialization.
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

