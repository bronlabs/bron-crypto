package signing_mrr21_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/sha256"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/keygen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing"
	signing_mrr21 "github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing/mrr21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// TestHappyPath runs every qualified quorum of a 2-of-3 key; the base-OT-only
// rVOLE is about ten times the cost of the extension, so the access
// structures and hashes are kept to one each.
func TestHappyPath(t *testing.T) {
	t.Parallel()
	accessStructure, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable(sharing.ID(1), sharing.ID(2), sharing.ID(3)).Freeze())
	require.NoError(t, err)

	t.Run("secp256k1", func(t *testing.T) {
		t.Parallel()
		suite, err := ecdsa.NewSuite(k256.NewCurve(), sha256.New)
		require.NoError(t, err)
		testHappyPath(t, suite, accessStructure)
	})
	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		suite, err := ecdsa.NewSuite(p256.NewCurve(), sha256.New)
		require.NoError(t, err)
		testHappyPath(t, suite, accessStructure)
	})
}

func testHappyPath[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, suite *ecdsa.Suite[P, B, S], accessStructure accessstructures.Monotone) {
	t.Helper()

	prng := pcg.NewRandomised()
	baseShards, err := trusteddealer.Deal(suite.Curve(), accessStructure, prng)
	require.NoError(t, err)
	shards := hashmap.NewComparable[sharing.ID, *dkls23.Shard[P, B, S]]()
	for id, baseShard := range baseShards.Iter() {
		shard, err := keygen.NewShard(baseShard)
		require.NoError(t, err)
		shards.Put(id, shard)
	}

	quorums := 0
	for ids := range sliceutils.KCoveringCombinations(accessStructure.Shareholders().List(), 1) {
		if !accessStructure.IsQualified(ids...) {
			continue
		}
		quorums++

		ctxs := session_testutils.MakeRandomContexts(t, hashset.NewComparable(ids...).Freeze(), prng)
		cosigners := make(map[sharing.ID]*signing_mrr21.Cosigner[P, B, S])
		for _, id := range ids {
			shard, _ := shards.Get(id)
			c, err := signing_mrr21.NewCosigner(ctxs[id], suite, shard, pcg.NewRandomised())
			require.NoError(t, err)
			cosigners[id] = c
		}
		message := []byte("Hello World")
		partialSignatures := runSigning(t, cosigners, message)

		s, ok := shards.Get(accessStructure.Shareholders().List()[0])
		require.True(t, ok)
		pk := s.PublicKey()

		offline, err := signing.NewNonCosigningAggregator(suite, pk, message)
		require.NoError(t, err)
		signature, err := offline.Aggregate(partialSignatures)
		require.NoError(t, err)
		require.NotNil(t, signature)
		for _, c := range cosigners {
			online, err := signing.NewCosigningAggregator(c.Core())
			require.NoError(t, err)
			own, err := online.Aggregate(partialSignatures)
			require.NoError(t, err)
			require.True(t, signature.Equal(own))
		}

		nativePk, err := pk.ToElliptic()
		require.NoError(t, err)
		nativeR, nativeS := signature.ToElliptic()
		digest, err := hashing.Hash(suite.HashFunc(), message)
		require.NoError(t, err)
		require.True(t, nativeEcdsa.Verify(nativePk, digest, nativeR, nativeS))

		var reference []byte
		for _, ctx := range ctxs {
			v, err := ctx.Transcript().ExtractBytes("test", 32)
			require.NoError(t, err)
			if reference == nil {
				reference = v
			}
			require.Equal(t, reference, v)
		}
	}
	require.Positive(t, quorums)
}

// runSigning drives the three rounds locally and returns the partial signatures.
func runSigning[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, cosigners map[sharing.ID]*signing_mrr21.Cosigner[P, B, S], message []byte) map[sharing.ID]*dkls23.PartialSignature[P, B, S] {
	tb.Helper()
	var err error
	participants := slices.Collect(maps.Values(cosigners))

	r1bOut := make(map[sharing.ID]*signing_mrr21.Round1Broadcast[P, B, S])
	r1uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing_mrr21.Round1P2P[P, B, S], *signing_mrr21.Cosigner[P, B, S]])
	for id, c := range cosigners {
		r1bOut[id], r1uOut[id], err = c.Round1()
		require.NoError(tb, err)
	}

	r2bIn, r2uIn := ntu.MapO2I(tb, participants, r1bOut, r1uOut)
	r2bOut := make(map[sharing.ID]*signing_mrr21.Round2Broadcast[P, B, S])
	r2uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing_mrr21.Round2P2P[P, B, S], *signing_mrr21.Cosigner[P, B, S]])
	for id, c := range cosigners {
		r2bOut[id], r2uOut[id], err = c.Round2(r2bIn[id], r2uIn[id])
		require.NoError(tb, err)
	}

	r3bIn, r3uIn := ntu.MapO2I(tb, participants, r2bOut, r2uOut)
	partialSignatures := make(map[sharing.ID]*dkls23.PartialSignature[P, B, S])
	for id, c := range cosigners {
		partialSignatures[id], err = c.Round3(r3bIn[id], r3uIn[id], message)
		require.NoError(tb, err)
	}
	return partialSignatures
}

// TestCosigningAggregatorRejectsSplitView checks the Segev nonce-consistency
// check on this instantiation as well: a partial signature on a different
// nonce point is refused and attributed to its sender.
func TestCosigningAggregatorRejectsSplitView(t *testing.T) {
	t.Parallel()
	suite, err := ecdsa.NewSuite(k256.NewCurve(), sha256.New)
	require.NoError(t, err)
	prng := pcg.NewRandomised()
	accessStructure, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable(sharing.ID(1), sharing.ID(2)).Freeze())
	require.NoError(t, err)
	baseShards, err := trusteddealer.Deal(suite.Curve(), accessStructure, prng)
	require.NoError(t, err)
	ids := accessStructure.Shareholders().List()
	ctxs := session_testutils.MakeRandomContexts(t, hashset.NewComparable(ids...).Freeze(), prng)
	cosigners := make(map[sharing.ID]*signing_mrr21.Cosigner[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for id, baseShard := range baseShards.Iter() {
		shard, err := keygen.NewShard(baseShard)
		require.NoError(t, err)
		cosigners[id], err = signing_mrr21.NewCosigner(ctxs[id], suite, shard, pcg.NewRandomised())
		require.NoError(t, err)
	}
	partialSignatures := runSigning(t, cosigners, []byte("split view"))

	const cheater = sharing.ID(1)
	honest := partialSignatures[cheater]
	forged, err := dkls23.NewPartialSignature(honest.R().Add(suite.Curve().Generator()), honest.U(), honest.W())
	require.NoError(t, err)
	tampered := maps.Clone(partialSignatures)
	tampered[cheater] = forged

	online, err := signing.NewCosigningAggregator(cosigners[sharing.ID(2)].Core())
	require.NoError(t, err)
	_, err = online.Aggregate(tampered)
	require.ErrorIs(t, err, base.ErrAbort)
	require.Equal(t, []sharing.ID{cheater}, base.GetMaliciousIdentities[sharing.ID](err))
	_, err = online.Aggregate(partialSignatures)
	require.NoError(t, err)
}
