package signing_mrr21_test

import (
	"bytes"
	"crypto/sha256"
	"maps"
	"slices"
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
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func TestRunner_HappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	quorum := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)

	baseShards, err := trusteddealer.Deal(curve, accessStructure, prng)
	require.NoError(t, err)
	shards := make(map[sharing.ID]*dkls23.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for id, baseShard := range baseShards.Iter() {
		shard, err := keygen.NewShard(baseShard)
		require.NoError(t, err)
		shards[id] = shard
	}

	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)
	message := []byte("hello from the dkls23 mrr21 sign runner")
	signingQuorum := hashset.NewComparable(quorum.List()[:2]...).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, signingQuorum, prng)

	runners := make(map[sharing.ID]network.Runner[*signing.SignResult[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for id := range signingQuorum.Iter() {
		shard, ok := shards[id]
		require.True(t, ok)
		runner, err := signing_mrr21.NewRunner(ctxs[id], suite, ntu.CBORRoundTrip(t, shard), message, pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = runner
	}

	results, notifications := ntu.TestExecuteRunners(t, runners)
	require.Len(t, results, signingQuorum.Size())
	ntu.RequireRoundCompletedNotifications(t, notifications, signingQuorum, signing_mrr21.ProtocolName, 3)

	partialSignatures := make(map[sharing.ID]*dkls23.PartialSignature[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for id, result := range results {
		require.NotNil(t, result.PartialSignature())
		require.NotNil(t, result.PartialSignatureCosigningAggregator())
		partialSignatures[id] = ntu.CBORRoundTrip(t, result.PartialSignature())
	}
	publicKey := slices.Collect(maps.Values(shards))[0].PublicKey()
	verifier, err := ecdsa.NewVerifier(suite)
	require.NoError(t, err)
	var expected *ecdsa.Signature[*k256.Scalar]
	for _, result := range results {
		signature, err := result.PartialSignatureCosigningAggregator().Aggregate(partialSignatures)
		require.NoError(t, err)
		require.NoError(t, verifier.Verify(signature, publicKey, message))
		if expected == nil {
			expected = signature
		}
		require.True(t, expected.Equal(signature))
	}

	transcriptValues := [][]byte{}
	for _, ctx := range ctxs {
		v, err := ctx.Transcript().ExtractBytes("test", 32)
		require.NoError(t, err)
		transcriptValues = append(transcriptValues, v)
	}
	for i := 1; i < len(transcriptValues); i++ {
		require.True(t, bytes.Equal(transcriptValues[i-1], transcriptValues[i]))
	}
}
