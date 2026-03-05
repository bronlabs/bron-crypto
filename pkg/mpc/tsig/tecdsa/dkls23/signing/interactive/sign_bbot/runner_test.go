package sign_bbot_test

import (
	"bytes"
	"crypto/sha256"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23"
	dkgTestutils "github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23/keygen/dkg/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23/signing/interactive/sign_bbot"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func TestRunner_HappyPath(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	accessStructure := makeAccessStructure(2, 2)
	shards := dkgTestutils.RunDKLs23DKG(t, curve, accessStructure)
	prng := pcg.NewRandomised()
	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)
	message := []byte("hello from dkls23 sign_bbot runner")
	quorum := accessStructure.Shareholders()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	runners := make(map[sharing.ID]network.Runner[*dkls23.PartialSignature[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for id := range quorum.Iter() {
		shard, ok := shards[id]
		require.True(t, ok)
		runner, err := sign_bbot.NewRunner(ctxs[id], suite, shard.Shard, message, pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = runner
	}

	partials := ntu.TestExecuteRunners(t, runners)
	require.Len(t, partials, quorum.Size())

	publicKey := slices.Collect(maps.Values(shards))[0].PublicKey()
	signature, err := dkls23.Aggregate(suite, publicKey, message, slices.Collect(maps.Values(partials))...)
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
