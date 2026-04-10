package signing_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/dealer"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr/lindell22/keygen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr/lindell22/signing"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/boolexpr"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/bip340"
)

func BenchmarkAggregator_Aggregate(b *testing.B) {
	const N = 12
	const (
		BRON sharing.ID = iota + 1
		CLIENT
		ORACLE1
		ORACLE2
		ORACLE3
		ORACLE4
		ORACLE5
		ORACLE6
		ORACLE7
		ORACLE8
		ORACLE9
		ORACLE10
	)

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	ac, err := boolexpr.NewThresholdGateAccessStructure(
		boolexpr.Or(
			boolexpr.And(
				boolexpr.ID(BRON),
				boolexpr.ID(CLIENT),
			),
			boolexpr.And(
				boolexpr.ID(BRON),
				boolexpr.Threshold(6, boolexpr.ID(ORACLE1), boolexpr.ID(ORACLE2), boolexpr.ID(ORACLE3), boolexpr.ID(ORACLE4), boolexpr.ID(ORACLE5), boolexpr.ID(ORACLE6), boolexpr.ID(ORACLE7), boolexpr.ID(ORACLE8), boolexpr.ID(ORACLE9), boolexpr.ID(ORACLE10)),
			),
			boolexpr.And(
				boolexpr.ID(CLIENT),
				boolexpr.Threshold(6, boolexpr.ID(ORACLE1), boolexpr.ID(ORACLE2), boolexpr.ID(ORACLE3), boolexpr.ID(ORACLE4), boolexpr.ID(ORACLE5), boolexpr.ID(ORACLE6), boolexpr.ID(ORACLE7), boolexpr.ID(ORACLE8), boolexpr.ID(ORACLE9), boolexpr.ID(ORACLE10)),
			),
		),
	)
	require.NoError(b, err)

	signingScheme, err := bip340.NewScheme(prng)
	require.NoError(b, err)
	variant := signingScheme.Variant()
	baseShards, err := dealer.DealBaseShards(curve, ac, prng)
	require.NoError(b, err)
	shards := hashmap.NewComparable[sharing.ID, *lindell22.Shard[*k256.Point, *k256.Scalar]]()
	for id, baseShard := range baseShards.Iter() {
		shard, err := keygen.NewShard(baseShard)
		require.NoError(b, err)
		shards.Put(id, shard)
	}

	cosignerIds := hashset.NewComparable(BRON, ORACLE1, ORACLE2, ORACLE3, ORACLE4, ORACLE5, ORACLE6).Freeze()
	ctxs := session_testutils.MakeRandomContexts(b, cosignerIds, prng)
	cosigners := make(map[sharing.ID]*signing.Cosigner[*k256.Point, *k256.Scalar, []byte])
	for id := range cosignerIds.Iter() {
		shard, _ := shards.Get(id)
		c, err := signing.NewCosigner(ctxs[id], shard, fiatshamir.Name, variant, pcg.NewRandomised())
		require.NoError(b, err)
		cosigners[id] = c
	}

	r1bOut := make(map[sharing.ID]*signing.Round1Broadcast[*k256.Point, *k256.Scalar, []byte])
	r1uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing.Round1P2P[*k256.Point, *k256.Scalar, []byte], *signing.Cosigner[*k256.Point, *k256.Scalar, []byte]])
	for id, c := range cosigners {
		r1bOut[id], r1uOut[id], err = c.Round1()
		require.NoError(b, err)
	}

	r2bIn, r2uIn := ntu.MapO2I(b, slices.Collect(maps.Values(cosigners)), r1bOut, r1uOut)
	r2bOut := make(map[sharing.ID]*signing.Round2Broadcast[*k256.Point, *k256.Scalar, []byte])
	for id, c := range cosigners {
		r2bOut[id], err = c.Round2(r2bIn[id], r2uIn[id])
		require.NoError(b, err)
	}

	r3bIn := ntu.MapBroadcastO2I(b, slices.Collect(maps.Values(cosigners)), r2bOut)
	partialSignatures := make(map[sharing.ID]*lindell22.PartialSignature[*k256.Point, *k256.Scalar])
	message := []byte("Hello World")
	for id, c := range cosigners {
		partialSignatures[id], err = c.Round3(r3bIn[id], message)
		require.NoError(b, err)
	}

	partialSignaturesMap := hashmap.NewComparableFromNativeLike(partialSignatures).Freeze()
	bronShard, _ := shards.Get(BRON)
	pk := bronShard.PublicKeyMaterial()
	b.Run("aggregate", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			aggregator, err := signing.NewAggregator(pk, signingScheme)
			require.NoError(b, err)
			_, err = aggregator.Aggregate(partialSignaturesMap, message)
			require.NoError(b, err)
		}
	})
	b.Run("cosigner aggregate", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			aggregator, err := signing.NewCosigningAggregator(cosigners[BRON], pk, signingScheme)
			require.NoError(b, err)
			_, err = aggregator.Aggregate(partialSignaturesMap, message)
			require.NoError(b, err)
		}
	})
}
