package signing_bbot_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/sha256"
	"hash"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/dealer"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/ecdsa/dkls23/keygen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/ecdsa/dkls23/signing_bbot"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

var TestHashFuncs = map[string]func() hash.Hash{
	"sha256": sha256.New,
}

var TestAccessStructures = testAccessStructures()

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for asName, as := range TestAccessStructures {
		t.Run(asName, func(t *testing.T) {
			t.Parallel()
			for hashFuncName, hashFunc := range TestHashFuncs {
				t.Run(hashFuncName, func(t *testing.T) {
					t.Parallel()

					t.Run("secp256k1", func(t *testing.T) {
						t.Parallel()
						suite, err := ecdsa.NewSuite(k256.NewCurve(), hashFunc)
						require.NoError(t, err)
						testHappyPath(t, suite, as)
					})
				})
			}
		})
	}
}

func testHappyPath[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, suite *ecdsa.Suite[P, B, S], accessStructure accessstructures.Monotone) {
	t.Helper()

	var err error
	prng := pcg.NewRandomised()
	baseShards, err := dealer.DealBaseShards(suite.Curve(), accessStructure, prng)
	require.NoError(t, err)
	shards := hashmap.NewComparable[sharing.ID, *dkls23.Shard[P, B, S]]()
	for id, baseShard := range baseShards.Iter() {
		shard, err := keygen.NewShard(baseShard)
		require.NoError(t, err)
		shards.Put(id, shard)
	}

	c := 0
	for ids := range sliceutils.KCoveringCombinations(accessStructure.Shareholders().List(), 1) {
		if !accessStructure.IsQualified(ids...) {
			continue
		}
		c++

		ctxs := session_testutils.MakeRandomContexts(t, hashset.NewComparable(ids...).Freeze(), prng)
		cosigners := make(map[sharing.ID]*signing_bbot.Cosigner[P, B, S])
		for _, id := range ids {
			shard, _ := shards.Get(id)
			c, err := signing_bbot.NewCosigner(ctxs[id], suite, shard, pcg.NewRandomised())
			require.NoError(t, err)
			cosigners[id] = c
		}

		// r1
		r1bOut := make(map[sharing.ID]*signing_bbot.Round1Broadcast[P, B, S])
		r1uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing_bbot.Round1P2P[P, B, S], *signing_bbot.Cosigner[P, B, S]])
		for id, c := range cosigners {
			r1bOut[id], r1uOut[id], err = c.Round1()
			require.NoError(t, err)
		}

		// r2
		r2bIn, r2uIn := ntu.MapO2I(t, slices.Collect(maps.Values(cosigners)), r1bOut, r1uOut)
		r2bOut := make(map[sharing.ID]*signing_bbot.Round2Broadcast[P, B, S])
		r2uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing_bbot.Round2P2P[P, B, S], *signing_bbot.Cosigner[P, B, S]])
		for id, c := range cosigners {
			r2bOut[id], r2uOut[id], err = c.Round2(r2bIn[id], r2uIn[id])
			require.NoError(t, err)
		}

		// r3
		r3bIn, r3uIn := ntu.MapO2I(t, slices.Collect(maps.Values(cosigners)), r2bOut, r2uOut)
		r3bOut := make(map[sharing.ID]*signing_bbot.Round3Broadcast[P, B, S])
		r3uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing_bbot.Round3P2P[P, B, S], *signing_bbot.Cosigner[P, B, S]])
		for id, c := range cosigners {
			r3bOut[id], r3uOut[id], err = c.Round3(r3bIn[id], r3uIn[id])
			require.NoError(t, err)
		}

		// r4
		r4bIn, r4uIn := ntu.MapO2I(t, slices.Collect(maps.Values(cosigners)), r3bOut, r3uOut)
		message := []byte("Hello World")
		partialSignatures := make(map[sharing.ID]*dkls23.PartialSignature[P, B, S])
		for id, c := range cosigners {
			partialSignatures[id], err = c.Round4(r4bIn[id], r4uIn[id], message)
			require.NoError(t, err)
		}

		s, ok := shards.Get(accessStructure.Shareholders().List()[0])
		require.True(t, ok)
		pk := s.PublicKey()
		signature, err := dkls23.Aggregate(suite, pk, message, slices.Collect(maps.Values(partialSignatures))...)
		require.NotNil(t, t, signature)
		require.NoError(t, err)

		nativePk := pk.ToElliptic()
		require.NotNil(t, nativePk)
		nativeR, nativeS := signature.ToElliptic()
		digest, err := hashing.Hash(suite.HashFunc(), message)
		require.NoError(t, err)
		ok = nativeEcdsa.Verify(nativePk, digest, nativeR, nativeS)
		require.True(t, ok)
	}
	require.Positive(t, c)
}

func testAccessStructures() map[string]accessstructures.Monotone {
	as1, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable(sharing.ID(1), sharing.ID(2), sharing.ID(3)).Freeze())
	if err != nil {
		panic(err)
	}

	return map[string]accessstructures.Monotone{
		"threshold": as1,
	}
}
