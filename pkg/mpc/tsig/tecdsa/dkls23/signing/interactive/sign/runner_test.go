package sign_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23"
	dkgTestutils "github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23/keygen/dkg/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23/signing/interactive/sign"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestRunner_HappyPath(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	accessStructure := makeAccessStructure(2, 3)
	shards := dkgTestutils.RunDKLs23DKG(t, curve, accessStructure)

	prng := pcg.NewRandomised()
	sessionID := ntu.MakeRandomSessionID(t, prng)
	tape := hagrid.NewTranscript(hex.EncodeToString(sessionID[:]))
	tapes := make(map[sharing.ID]transcripts.Transcript)

	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)
	message := []byte("hello from dkls23 sign runner")
	quorum := accessStructure.Shareholders()

	runners := make(map[sharing.ID]network.Runner[*dkls23.PartialSignature[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for id := range quorum.Iter() {
		shard, ok := shards[id]
		require.True(t, ok)
		tapes[id] = tape.Clone()
		runner, err := sign.NewRunner(sessionID, quorum, suite, shard, message, pcg.NewRandomised(), tapes[id])
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

	transcriptValues := make([][]byte, 0, len(tapes))
	for _, tr := range tapes {
		v, err := tr.ExtractBytes("test", 32)
		require.NoError(t, err)
		transcriptValues = append(transcriptValues, v)
	}
	for i := 1; i < len(transcriptValues); i++ {
		require.True(t, bytes.Equal(transcriptValues[i-1], transcriptValues[i]))
	}
}
