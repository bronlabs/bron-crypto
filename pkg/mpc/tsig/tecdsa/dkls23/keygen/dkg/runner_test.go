package dkg_test

import (
	"bytes"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	gennaroTU "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

func TestRunner_HappyPath(t *testing.T) {
	t.Parallel()
	var err error

	const thresh = 2
	const total = 3

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	accessStructure, err := threshold.NewThresholdAccessStructure(thresh, hashset.NewComparable[sharing.ID](1, 2, 3).Freeze())
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, accessStructure.Shareholders(), prng)

	gennaroParticipants := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], accessStructure.Shareholders().Size())
	for id, ctx := range ctxs {
		gennaroParticipants[id], err = gennaro.NewParticipant(ctx, curve, accessStructure, fiatshamir.Name, prng)
		require.NoError(t, err)
	}
	dkgOutputs := gennaroTU.DoGennaroDKG(t, gennaroParticipants)

	runners := make(map[sharing.ID]network.Runner[*dkls23.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for id, dkgOutput := range dkgOutputs {
		baseShard, err := tecdsa.NewShard(dkgOutput.Share(), dkgOutput.VerificationVector(), accessStructure)
		require.NoError(t, err)

		runner, err := dkg.NewRunner(ctxs[id], baseShard, prng)
		require.NoError(t, err)
		runners[id] = runner
	}

	shards := ntu.TestExecuteRunners(t, runners)
	require.Len(t, shards, total)

	publicKeys := make([]*k256.Point, 0, total)
	for _, shard := range shards {
		publicKeys = append(publicKeys, shard.PublicKey().Value())
	}
	for i := 1; i < len(publicKeys); i++ {
		require.True(t, publicKeys[0].Equal(publicKeys[i]))
	}

	for th := accessStructure.Threshold(); th <= uint(accessStructure.Shareholders().Size()); th++ {
		for shardsSubset := range sliceutils.Combinations(slices.Collect(maps.Values(shards)), th) {
			feldmanScheme, err := feldman.NewScheme(curve.Generator(), accessStructure)
			require.NoError(t, err)
			sharesSubset := sliceutils.Map(shardsSubset, func(s *dkls23.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]) *feldman.Share[*k256.Scalar] {
				return s.Share()
			})
			recoveredSk, err := feldmanScheme.Reconstruct(sharesSubset...)
			require.NoError(t, err)
			recoveredPk := curve.ScalarBaseMul(recoveredSk.Value())
			require.True(t, recoveredPk.Equal(publicKeys[0]))
		}
	}

	transcriptValues := make(map[sharing.ID][]byte)
	for id, ctx := range ctxs {
		v, err := ctx.Transcript().ExtractBytes("test", 32)
		require.NoError(t, err)
		transcriptValues[id] = v
	}
	tr := slices.Collect(maps.Values(transcriptValues))
	for i := 1; i < len(transcriptValues); i++ {
		require.True(t, bytes.Equal(tr[i-1], tr[i]))
	}
}
