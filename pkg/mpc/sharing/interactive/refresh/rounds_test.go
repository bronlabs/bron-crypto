package refresh_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/interactive/refresh"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, 3)
	as, err := accessstructures.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)
	curve := k256.NewCurve()

	scheme, err := feldman.NewScheme(curve.Generator(), as)
	require.NoError(t, err)
	secretValue, err := k256.NewScalarField().Random(prng)
	require.NoError(t, err)
	secret := feldman.NewSecret(secretValue)
	dealerOut, err := scheme.Deal(secret, prng)
	require.NoError(t, err)

	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	participants := make(map[sharing.ID]*refresh.Participant[*k256.Point, *k256.Scalar])
	for id, ctx := range ctxs {
		share, ok := dealerOut.Shares().Get(id)
		require.True(t, ok)
		shard, err := tsig.NewBaseShard(share, dealerOut.VerificationMaterial(), as)
		require.NoError(t, err)
		participants[id], err = refresh.NewParticipant(ctx, shard, prng)
		require.NoError(t, err)
	}

	r1bo := make(map[sharing.ID]*refresh.Round1Broadcast[*k256.Point, *k256.Scalar])
	r1uo := make(map[sharing.ID]network.RoundMessages[*refresh.Round1P2P[*k256.Point, *k256.Scalar]])
	for id, p := range participants {
		r1bo[id], r1uo[id], err = p.Round1()
		require.NoError(t, err)
	}

	r2bi, r2ui := ntu.MapO2I(t, slices.Collect(maps.Values(participants)), r1bo, r1uo)
	shares := make(map[sharing.ID]*feldman.Share[*k256.Scalar])
	verificationVectors := make(map[sharing.ID]feldman.VerificationVector[*k256.Point, *k256.Scalar])
	for id, p := range participants {
		out, err := p.Round2(r2bi[id], r2ui[id])
		require.NoError(t, err)
		err = scheme.Verify(out.Share(), out.VerificationVector())
		require.NoError(t, err)
		shares[id] = out.Share()
		verificationVectors[id] = out.VerificationVector()
	}

	t.Run("should generate valid shares", func(t *testing.T) {
		t.Parallel()
		recovered, err := scheme.Reconstruct(slices.Collect(maps.Values(shares))...)
		require.NoError(t, err)
		require.True(t, recovered.Value().Equal(secretValue))
	})

	t.Run("should generate valid verification vectors", func(t *testing.T) {
		t.Parallel()
		vs := slices.Collect(maps.Values(verificationVectors))
		require.Len(t, vs, 3)
		for i := range vs {
			if i > 0 {
				require.True(t, vs[i-1].Equal(vs[i]))
			}
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
