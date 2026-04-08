package signing_bbot_test

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
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/dealer"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/ecdsa/dkls23/keygen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/ecdsa/dkls23/signing_bbot"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
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

	baseShards, err := dealer.DealBaseShards(curve, accessStructure, prng)
	require.NoError(t, err)
	shards := make(map[sharing.ID]*dkls23.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for id, baseShard := range baseShards.Iter() {
		shard, err := keygen.NewShard(baseShard)
		require.NoError(t, err)
		shards[id] = shard
	}

	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)
	message := []byte("hello from dkls23 sign runner")
	signingQuorum := hashset.NewComparable(quorum.List()[:2]...).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, signingQuorum, prng)

	runners := make(map[sharing.ID]network.Runner[*dkls23.PartialSignature[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for id := range signingQuorum.Iter() {
		shard, ok := shards[id]
		require.True(t, ok)
		runner, err := signing_bbot.NewRunner(ctxs[id], suite, ntu.CBORRoundTrip(t, shard), message, pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = runner
	}

	partialSignatures := ntu.TestExecuteRunners(t, runners)
	require.Len(t, partialSignatures, signingQuorum.Size())

	publicKey := slices.Collect(maps.Values(shards))[0].PublicKey()
	signature, err := dkls23.Aggregate(suite, publicKey, message, slices.Collect(maps.Values(partialSignatures))...)
	require.NoError(t, err)
	require.NotNil(t, signature)
	verifier, err := ecdsa.NewVerifier(suite)
	require.NoError(t, err)
	err = verifier.Verify(signature, publicKey, message)
	require.NoError(t, err)

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
