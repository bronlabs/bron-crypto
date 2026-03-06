package refresh_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/refresh"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func TestRunner_HappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, 3)
	as, err := accessstructures.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	curve := k256.NewCurve()
	scheme, err := feldman.NewScheme(curve.Generator(), as)
	require.NoError(t, err)

	secretValue, err := k256.NewScalarField().Random(prng)
	require.NoError(t, err)
	secret := feldman.NewSecret(secretValue)
	dealerOut, err := scheme.Deal(secret, prng)
	require.NoError(t, err)

	runners := make(map[sharing.ID]network.Runner[*refresh.Output[*k256.Point, *k256.Scalar]])
	for id, ctx := range ctxs {
		share, ok := dealerOut.Shares().Get(id)
		require.True(t, ok)

		shard, err := tsig.NewBaseShard(share, dealerOut.VerificationMaterial(), as)
		require.NoError(t, err)

		// Use independent PRNGs because runners execute concurrently.
		runner, err := refresh.NewRunner(ctx, shard, pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = runner
	}

	outputs := ntu.TestExecuteRunners(t, runners)
	require.Len(t, outputs, len(ctxs))

	shares := make(map[sharing.ID]*feldman.Share[*k256.Scalar], len(outputs))
	verificationVectors := make(map[sharing.ID]feldman.VerificationVector[*k256.Point, *k256.Scalar], len(outputs))
	for id, output := range outputs {
		require.NotNil(t, output)
		err := scheme.Verify(output.Share(), output.VerificationVector())
		require.NoError(t, err)

		shares[id] = output.Share()
		verificationVectors[id] = output.VerificationVector()
	}

	t.Run("should generate valid shares", func(t *testing.T) {
		t.Parallel()
		recovered, err := scheme.Reconstruct(slices.Collect(maps.Values(shares))...)
		require.NoError(t, err)
		require.True(t, recovered.Value().Equal(secretValue))
	})

	t.Run("should generate valid verification vectors", func(t *testing.T) {
		t.Parallel()
		var first feldman.VerificationVector[*k256.Point, *k256.Scalar]
		for _, vv := range verificationVectors {
			if first == nil {
				first = vv
				continue
			}
			require.True(t, first.Equal(vv))
		}
	})

	t.Run("should generate valid transcripts", func(t *testing.T) {
		t.Parallel()

		samples := make(map[sharing.ID][]byte)
		for id, ctx := range ctxs {
			samples[id], err = ctx.Transcript().ExtractBytes("sample", 32)
			require.NoError(t, err)
		}
		samplesList := slices.Collect(maps.Values(samples))
		for i := range samplesList {
			if i > 0 {
				require.True(t, slices.Equal(samplesList[i-1], samplesList[i]))
			}
		}
	})
}
