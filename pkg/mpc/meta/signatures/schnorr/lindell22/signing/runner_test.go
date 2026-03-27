package signing_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22/signing"
	ltu "github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/bip340"
)

func TestRunnerHappyPath_BIP340(t *testing.T) {
	t.Parallel()

	const thresh = 2
	const total = 3

	prng := pcg.NewRandomised()
	group := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	accessStructure, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	require.NoError(t, err)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar])
	for id := range shareholders.Iter() {
		party, err := gennaro.NewParticipant(ctxs[id], group, accessStructure, fiatshamir.Name, pcg.NewRandomised())
		require.NoError(t, err)
		parties[id] = party
	}

	shards := ltu.DoLindell22DKG(t, parties)
	require.Len(t, shards, total)

	signingCtxs := ctxs
	message := []byte("Hello from Lindell22 runner")
	variant := scheme.Variant()

	runners := make(map[sharing.ID]network.Runner[*lindell22.PartialSignature[*k256.Point, *k256.Scalar]], total)
	for id, ctx := range signingCtxs {
		shard, ok := shards[id]
		require.True(t, ok)

		runner, err := signing.NewRunner(ctx, shard, fiatshamir.Name, variant, message, pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = runner
	}

	partialSignatures := ntu.TestExecuteRunners(t, runners)
	require.Len(t, partialSignatures, total)

	anyID := shareholders.List()[0]
	publicMaterial, ok := shards[anyID]
	require.True(t, ok)

	aggregator, err := signing.NewAggregator(publicMaterial.PublicKeyMaterial(), scheme)
	require.NoError(t, err)

	sig, err := aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSignatures).Freeze(), message)
	require.NoError(t, err)
	require.NotNil(t, sig)

	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(sig, publicMaterial.PublicKey(), message)
	require.NoError(t, err)

	firstTapeBytes, err := ctxs[anyID].Transcript().ExtractBytes("test", 32)
	require.NoError(t, err)
	for id, ctx := range ctxs {
		if id == anyID {
			continue
		}
		b, err := ctx.Transcript().ExtractBytes("test", 32)
		require.NoError(t, err)
		require.True(t, slices.Equal(firstTapeBytes, b))
	}
}
