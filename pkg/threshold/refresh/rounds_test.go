package refresh_test

import (
	crand "crypto/rand"
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/refresh"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	ids := []sharing.ID{1, 2, 3}
	sharingIds := hashset.NewComparable[sharing.ID](ids...).Freeze()
	as, err := shamir.NewAccessStructure(2, sharingIds)
	require.NoError(t, err)
	curve := k256.NewCurve()
	scheme, err := feldman.NewScheme(curve.Generator(), 2, sharingIds)
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
	participants[0], err = refresh.NewParticipant(sid, s0, dealerOut.VerificationMaterial(), as, tapes[0], prng)

	s1, ok := dealerOut.Shares().Get(2)
	require.True(t, ok)
	participants[1], err = refresh.NewParticipant(sid, s1, dealerOut.VerificationMaterial(), as, tapes[1], prng)

	s2, ok := dealerOut.Shares().Get(3)
	require.True(t, ok)
	participants[2], err = refresh.NewParticipant(sid, s2, dealerOut.VerificationMaterial(), as, tapes[2], prng)

	r1bo := make(map[sharing.ID]*refresh.Round1Broadcast[*k256.Point, *k256.Scalar])
	r1uo := make(map[sharing.ID]network.RoundMessages[*refresh.Round1P2P[*k256.Point, *k256.Scalar]])
	for _, p := range participants {
		r1bo[p.SharingID()], r1uo[p.SharingID()], err = p.Round1()
		require.NoError(t, err)
	}

	r2bi, r2ui := testutils.MapO2I(t, participants, r1bo, r1uo)
	shares := make(map[sharing.ID]*feldman.Share[*k256.Scalar])
	verificationVectors := make(map[sharing.ID]feldman.VerificationVector[*k256.Point, *k256.Scalar])
	for _, p := range participants {
		s, v, err := p.Round2(r2bi[p.SharingID()], r2ui[p.SharingID()])
		require.NoError(t, err)
		err = scheme.Verify(s, v)
		require.NoError(t, err)
		shares[p.SharingID()] = s
		verificationVectors[p.SharingID()] = v
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
