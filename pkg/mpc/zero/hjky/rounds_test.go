package hjky_test

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
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, 3)
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	as, err := accessstructures.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)
	curve := k256.NewCurve()

	participants := make(map[sharing.ID]*hjky.Participant[*k256.Point, *k256.Scalar])
	for id, ctx := range ctxs {
		participants[id], err = hjky.NewParticipant(ctx, as, curve, prng)
		require.NoError(t, err)
	}

	r1bo := make(map[sharing.ID]*hjky.Round1Broadcast[*k256.Point, *k256.Scalar])
	r1uo := make(map[sharing.ID]network.RoundMessages[*hjky.Round1P2P[*k256.Point, *k256.Scalar]])
	for id, p := range participants {
		r1bo[id], r1uo[id], err = p.Round1()
		require.NoError(t, err)
	}

	r2bi, r2ui := ntu.MapO2I(t, slices.Collect(maps.Values(participants)), r1bo, r1uo)
	shares := make(map[sharing.ID]*feldman.Share[*k256.Scalar])
	verificationVectors := make(map[sharing.ID]feldman.VerificationVector[*k256.Point, *k256.Scalar])
	for id, p := range participants {
		shares[id], verificationVectors[id], err = p.Round2(r2bi[id], r2ui[id])
		require.NoError(t, err)
	}

	t.Run("should generate valid shares", func(t *testing.T) {
		t.Parallel()

		scheme, err := feldman.NewScheme(k256.NewCurve().Generator(), as)
		require.NoError(t, err)
		zero, err := scheme.Reconstruct(slices.Collect(maps.Values(shares))...)
		require.NoError(t, err)
		require.True(t, zero.Value().Equal(k256.NewScalarField().Zero()))
	})

	t.Run("should generate valid verification vectors", func(t *testing.T) {
		t.Parallel()

		vs := slices.Collect(maps.Values(verificationVectors))
		for i := range vs {
			if i > 0 {
				require.True(t, vs[i-1].Equal(vs[i]))
			}
		}
	})

	t.Run("transcripts match", func(t *testing.T) {
		t.Parallel()

		data := make([][]byte, as.Shareholders().Size())
		for i, ctx := range slices.Collect(maps.Values(ctxs)) {
			data[i], err = ctx.Transcript().ExtractBytes("test", 32)
			require.NoError(t, err)
			if i > 0 {
				require.True(t, slices.Equal(data[i-1], data[i]))
			}
		}
	})
}
