package signing_softspoken_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha3"
	"hash"
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
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/boolexpr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/keygen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing"
	signing_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

var testHashFuncs = map[string]func() hash.Hash{
	"sha256":   sha256.New,
	"sha3_512": hashing.HashFuncTypeErase(sha3.New512),
}

var testAccessStructures = makeTestAccessStructures()

func TestHappyPath(t *testing.T) {
	t.Parallel()

	for asName, as := range testAccessStructures {
		t.Run(asName, func(t *testing.T) {
			t.Parallel()
			for hashFuncName, hashFunc := range testHashFuncs {
				t.Run(hashFuncName, func(t *testing.T) {
					t.Parallel()

					t.Run("secp256k1", func(t *testing.T) {
						t.Parallel()
						suite, err := ecdsa.NewSuite(k256.NewCurve(), hashFunc)
						require.NoError(t, err)
						testHappyPath(t, suite, as)
					})
					t.Run("P256", func(t *testing.T) {
						t.Parallel()
						suite, err := ecdsa.NewSuite(p256.NewCurve(), hashFunc)
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
		cosigners := make(map[sharing.ID]*signing_softspoken.Cosigner[P, B, S])
		for _, id := range ids {
			shard, _ := shards.Get(id)
			c, err := signing_softspoken.NewCosigner(ctxs[id], suite, shard, pcg.NewRandomised())
			require.NoError(t, err)
			cosigners[id] = c
		}
		message := []byte("Hello World")
		partialSignatures := runSigning(t, cosigners, message)

		s, ok := shards.Get(accessStructure.Shareholders().List()[0])
		require.True(t, ok)
		pk := s.PublicKey()

		// Every cosigner aggregates with its own session state, an outsider
		// without any, and all must agree.
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

		// Every party ends with the same session transcript.
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

// runSigning drives the four rounds locally and returns the partial signatures.
func runSigning[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, cosigners map[sharing.ID]*signing_softspoken.Cosigner[P, B, S], message []byte) map[sharing.ID]*dkls23.PartialSignature[P, B, S] {
	tb.Helper()
	var err error
	participants := slices.Collect(maps.Values(cosigners))

	r1bOut := make(map[sharing.ID]*signing_softspoken.Round1Broadcast[P, B, S])
	r1uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing_softspoken.Round1P2P[P, B, S], *signing_softspoken.Cosigner[P, B, S]])
	for id, c := range cosigners {
		r1bOut[id], r1uOut[id], err = c.Round1()
		require.NoError(tb, err)
	}

	r2bIn, r2uIn := ntu.MapO2I(tb, participants, r1bOut, r1uOut)
	r2uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing_softspoken.Round2P2P[P, B, S], *signing_softspoken.Cosigner[P, B, S]])
	for id, c := range cosigners {
		r2uOut[id], err = c.Round2(r2bIn[id], r2uIn[id])
		require.NoError(tb, err)
	}

	r3uIn := ntu.MapUnicastO2I(tb, participants, r2uOut)
	r3bOut := make(map[sharing.ID]*signing_softspoken.Round3Broadcast[P, B, S])
	r3uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing_softspoken.Round3P2P[P, B, S], *signing_softspoken.Cosigner[P, B, S]])
	for id, c := range cosigners {
		r3bOut[id], r3uOut[id], err = c.Round3(r3uIn[id])
		require.NoError(tb, err)
	}

	r4bIn, r4uIn := ntu.MapO2I(tb, participants, r3bOut, r3uOut)
	partialSignatures := make(map[sharing.ID]*dkls23.PartialSignature[P, B, S])
	for id, c := range cosigners {
		partialSignatures[id], err = c.Round4(r4bIn[id], r4uIn[id], message)
		require.NoError(tb, err)
	}
	return partialSignatures
}

// TestAggregatorsRejectSplitView plays the adversary of Segev (eprint 2026/929,
// Section 4) at the output step: one party hands another a partial signature
// built on a different nonce point. Both aggregators must refuse, and the
// cosigning one must name the party.
func TestAggregatorsRejectSplitView(t *testing.T) {
	t.Parallel()
	suite, err := ecdsa.NewSuite(k256.NewCurve(), sha256.New)
	require.NoError(t, err)
	prng := pcg.NewRandomised()
	accessStructure, err := threshold.NewThresholdAccessStructure(3, hashset.NewComparable(sharing.ID(1), sharing.ID(2), sharing.ID(3)).Freeze())
	require.NoError(t, err)
	baseShards, err := trusteddealer.Deal(suite.Curve(), accessStructure, prng)
	require.NoError(t, err)
	ids := accessStructure.Shareholders().List()
	ctxs := session_testutils.MakeRandomContexts(t, hashset.NewComparable(ids...).Freeze(), prng)
	cosigners := make(map[sharing.ID]*signing_softspoken.Cosigner[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	var pk *ecdsa.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	for id, baseShard := range baseShards.Iter() {
		shard, err := keygen.NewShard(baseShard)
		require.NoError(t, err)
		pk = shard.PublicKey()
		cosigners[id], err = signing_softspoken.NewCosigner(ctxs[id], suite, shard, pcg.NewRandomised())
		require.NoError(t, err)
	}
	message := []byte("split view")
	partialSignatures := runSigning(t, cosigners, message)

	// Party 1 claims a different nonce point: R + G with the same shares.
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

	offline, err := signing.NewNonCosigningAggregator(suite, pk, message)
	require.NoError(t, err)
	_, err = offline.Aggregate(tampered)
	require.ErrorIs(t, err, base.ErrAbort)

	// A share that passes the nonce check but breaks the signature is caught
	// by the sign-consistency and verification steps, without attribution.
	broken, err := dkls23.NewPartialSignature(honest.R(), honest.U().Add(suite.ScalarField().One()), honest.W())
	require.NoError(t, err)
	tampered[cheater] = broken
	online, err = signing.NewCosigningAggregator(cosigners[sharing.ID(3)].Core())
	require.NoError(t, err)
	_, err = online.Aggregate(tampered)
	require.ErrorIs(t, err, base.ErrAbort)
	_, err = offline.Aggregate(tampered)
	require.ErrorIs(t, err, base.ErrAbort)

	// Aggregating succeeds exactly once per cosigner: the state is consumed.
	online, err = signing.NewCosigningAggregator(cosigners[sharing.ID(2)].Core())
	require.NoError(t, err)
	_, err = online.Aggregate(partialSignatures)
	require.NoError(t, err)
	_, err = online.Aggregate(partialSignatures)
	require.ErrorIs(t, err, signing.ErrRound)
}

func makeTestAccessStructures() map[string]accessstructures.Monotone {
	as1, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable(sharing.ID(1), sharing.ID(2), sharing.ID(3)).Freeze())
	if err != nil {
		panic(err)
	}
	as2, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
		hierarchical.WithLevel(1, sharing.ID(1), sharing.ID(2)),
		hierarchical.WithLevel(2, sharing.ID(3), sharing.ID(4)),
	)
	if err != nil {
		panic(err)
	}
	as3, err := boolexpr.NewThresholdGateAccessStructure(
		boolexpr.Or(
			boolexpr.And(boolexpr.ID(sharing.ID(1)), boolexpr.ID(sharing.ID(2))),
			boolexpr.And(boolexpr.ID(sharing.ID(3)), boolexpr.ID(sharing.ID(4))),
		),
	)
	if err != nil {
		panic(err)
	}
	return map[string]accessstructures.Monotone{
		"threshold":    as1,
		"hierarchical": as2,
		"gate":         as3,
	}
}
