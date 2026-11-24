package signing_mrr21_test

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/keygen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing"
	signing_mrr21 "github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing/mrr21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

type (
	point     = *k256.Point
	baseField = *k256.BaseFieldElement
	scalar    = *k256.Scalar
)

// BenchmarkSigning measures one full signing on base OTs alone and the
// aggregation, all parties computed sequentially in one goroutine and messages
// passed in memory, with t signers of a t-of-(t+1) threshold key on secp256k1.
func BenchmarkSigning(b *testing.B) {
	for _, signers := range []int{2, 3} {
		b.Run(fmt.Sprintf("%d-signers", signers), func(b *testing.B) { benchmarkSigning(b, signers) })
	}
}

func benchmarkSetup(tb testing.TB, signers int) (*ecdsa.Suite[point, baseField, scalar], map[sharing.ID]*dkls23.Shard[point, baseField, scalar], network.Quorum) {
	tb.Helper()
	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(uint(signers + 1))
	accessStructure, err := threshold.NewThresholdAccessStructure(uint(signers), shareholders)
	require.NoError(tb, err)
	baseShards, err := trusteddealer.Deal(curve, accessStructure, prng)
	require.NoError(tb, err)
	shards := make(map[sharing.ID]*dkls23.Shard[point, baseField, scalar])
	for id, baseShard := range baseShards.Iter() {
		shards[id], err = keygen.NewShard(baseShard)
		require.NoError(tb, err)
	}
	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(tb, err)
	return suite, shards, hashset.NewComparable(shareholders.List()[:signers]...).Freeze()
}

func benchmarkSigning(b *testing.B, signers int) {
	b.Helper()
	suite, shards, quorum := benchmarkSetup(b, signers)
	prng := pcg.NewRandomised()
	message := []byte("benchmark")
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		ctxs := session_testutils.MakeRandomContexts(b, quorum, prng)
		b.StartTimer()
		cosigners := make(map[sharing.ID]*signing_mrr21.Cosigner[point, baseField, scalar])
		for id := range quorum.Iter() {
			var err error
			cosigners[id], err = signing_mrr21.NewCosigner(ctxs[id], suite, shards[id], prng)
			require.NoError(b, err)
		}
		partialSignatures := runSigning(b, cosigners, message)
		aggregator, err := signing.NewCosigningAggregator(cosigners[quorum.List()[0]].Core())
		require.NoError(b, err)
		_, err = aggregator.Aggregate(partialSignatures)
		require.NoError(b, err)
	}
}
