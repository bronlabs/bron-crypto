package refresh_test

import (
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/interactive/refresh"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	ids := []sharing.ID{1, 2, 3}
	sharingIDs := hashset.NewComparable(ids...).Freeze()
	as, err := accessstructures.NewThresholdAccessStructure(2, sharingIDs)
	require.NoError(t, err)
	curve := k256.NewCurve()
	scheme, err := feldman.NewScheme(curve.Generator(), as)
	require.NoError(t, err)
	secretValue, err := k256.NewScalarField().Random(prng)
	require.NoError(t, err)
	secret := feldman.NewSecret(secretValue)
	dealerOut, err := scheme.Deal(secret, prng)
	require.NoError(t, err)
	var sid network.SID
	_, err = io.ReadFull(prng, sid[:])
	require.NoError(t, err)

	tapes := make([]transcripts.Transcript, 3)
	tapes[0] = hagrid.NewTranscript("test")
	tapes[1] = hagrid.NewTranscript("test")
	tapes[2] = hagrid.NewTranscript("test")

	participants := make([]*refresh.Participant[*k256.Point, *k256.Scalar], 3)

	s0, ok := dealerOut.Shares().Get(1)
	require.True(t, ok)
	sh0, err := tsig.NewBaseShard(s0, dealerOut.VerificationMaterial(), as)
	require.NoError(t, err)
	participants[0], err = refresh.NewParticipant(sid, sh0, tapes[0], prng)
	require.NoError(t, err)

	s1, ok := dealerOut.Shares().Get(2)
	require.True(t, ok)
	sh1, err := tsig.NewBaseShard(s1, dealerOut.VerificationMaterial(), as)
	require.NoError(t, err)
	participants[1], err = refresh.NewParticipant(sid, sh1, tapes[1], prng)
	require.NoError(t, err)

	s2, ok := dealerOut.Shares().Get(3)
	require.True(t, ok)
	sh2, err := tsig.NewBaseShard(s2, dealerOut.VerificationMaterial(), as)
	require.NoError(t, err)
	participants[2], err = refresh.NewParticipant(sid, sh2, tapes[2], prng)
	require.NoError(t, err)

	r1bo := make(map[sharing.ID]*refresh.Round1Broadcast[*k256.Point, *k256.Scalar])
	r1uo := make(map[sharing.ID]network.RoundMessages[*refresh.Round1P2P[*k256.Point, *k256.Scalar]])
	for _, p := range participants {
		r1bo[p.SharingID()], r1uo[p.SharingID()], err = p.Round1()
		require.NoError(t, err)
	}

	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)
	shares := make(map[sharing.ID]*feldman.Share[*k256.Scalar])
	verificationVectors := make(map[sharing.ID]feldman.VerificationVector[*k256.Point, *k256.Scalar])
	for _, p := range participants {
		out, err := p.Round2(r2bi[p.SharingID()], r2ui[p.SharingID()])
		require.NoError(t, err)
		err = scheme.Verify(out.Share(), out.VerificationVector())
		require.NoError(t, err)
		shares[p.SharingID()] = out.Share()
		verificationVectors[p.SharingID()] = out.VerificationVector()
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
		t0Bytes, err := tapes[0].ExtractBytes("test", 32)
		require.NoError(t, err)
		t1Bytes, err := tapes[1].ExtractBytes("test", 32)
		require.NoError(t, err)
		t2Bytes, err := tapes[2].ExtractBytes("test", 32)
		require.NoError(t, err)
		require.True(t, slices.Equal(t0Bytes, t1Bytes))
		require.True(t, slices.Equal(t1Bytes, t2Bytes))
	})
}
