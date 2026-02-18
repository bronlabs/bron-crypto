package refresh_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/refresh"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestRunner_HappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	ids := []sharing.ID{1, 2, 3}
	sharingIDs := hashset.NewComparable(ids...).Freeze()
	as, err := sharing.NewThresholdAccessStructure(2, sharingIDs)
	require.NoError(t, err)

	curve := k256.NewCurve()
	scheme, err := feldman.NewScheme(curve.Generator(), 2, sharingIDs)
	require.NoError(t, err)

	secretValue, err := k256.NewScalarField().Random(prng)
	require.NoError(t, err)
	secret := feldman.NewSecret(secretValue)
	dealerOut, err := scheme.Deal(secret, prng)
	require.NoError(t, err)

	sid := ntu.MakeRandomSessionID(t, prng)

	tapes := map[sharing.ID]transcripts.Transcript{
		1: hagrid.NewTranscript("test"),
		2: hagrid.NewTranscript("test"),
		3: hagrid.NewTranscript("test"),
	}

	runners := make(map[sharing.ID]network.Runner[*refresh.Output[*k256.Point, *k256.Scalar]])
	for _, id := range ids {
		share, ok := dealerOut.Shares().Get(id)
		require.True(t, ok)

		shard, err := tsig.NewBaseShard(share, dealerOut.VerificationMaterial(), as)
		require.NoError(t, err)

		// Use independent PRNGs because runners execute concurrently.
		runner, err := refresh.NewRunner(sid, shard, tapes[id], pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = runner
	}

	outputs := ntu.TestExecuteRunners(t, runners)
	require.Len(t, outputs, len(ids))

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
		firstBytes, err := tapes[ids[0]].ExtractBytes("test", 32)
		require.NoError(t, err)

		for _, id := range ids[1:] {
			b, err := tapes[id].ExtractBytes("test", 32)
			require.NoError(t, err)
			require.True(t, slices.Equal(firstBytes, b))
		}
	})
}
