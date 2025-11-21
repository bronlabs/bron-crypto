package hjky_test

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
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	as, err := shamir.NewAccessStructure(2, hashset.NewComparable[sharing.ID](1, 2, 3).Freeze())
	require.NoError(t, err)
	prng := crand.Reader
	var sessionId network.SID
	_, err = io.ReadFull(prng, sessionId[:])
	require.NoError(t, err)
	curve := k256.NewCurve()

	tapes := make([]transcripts.Transcript, as.Shareholders().Size())
	tapes[0] = hagrid.NewTranscript("test")
	tapes[1] = hagrid.NewTranscript("test")
	tapes[2] = hagrid.NewTranscript("test")

	participants := make([]*hjky.Participant[*k256.Point, *k256.Scalar], as.Shareholders().Size())
	participants[0], err = hjky.NewParticipant(sessionId, 1, as, curve, tapes[0], prng)
	require.NoError(t, err)
	participants[1], err = hjky.NewParticipant(sessionId, 2, as, curve, tapes[1], prng)
	require.NoError(t, err)
	participants[2], err = hjky.NewParticipant(sessionId, 3, as, curve, tapes[2], prng)

	r1bo := make(map[sharing.ID]*hjky.Round1Broadcast[*k256.Point, *k256.Scalar])
	r1uo := make(map[sharing.ID]network.RoundMessages[*hjky.Round1P2P[*k256.Point, *k256.Scalar]])
	for _, p := range participants {
		r1bo[p.SharingID()], r1uo[p.SharingID()], err = p.Round1()
		require.NoError(t, err)
	}

	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)
	shares := make(map[sharing.ID]*feldman.Share[*k256.Scalar])
	verificationVectors := make(map[sharing.ID]feldman.VerificationVector[*k256.Point, *k256.Scalar])
	for _, p := range participants {
		shares[p.SharingID()], verificationVectors[p.SharingID()], err = p.Round2(r2bi[p.SharingID()], r2ui[p.SharingID()])
		require.NoError(t, err)
	}

	t.Run("should generate valid shares", func(t *testing.T) {
		t.Parallel()

		scheme, err := feldman.NewScheme(k256.NewCurve().Generator(), as.Threshold(), as.Shareholders())
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
		for i, tape := range tapes {
			data[i], err = tape.ExtractBytes("test", 32)
			require.NoError(t, err)
			if i > 0 {
				require.True(t, slices.Equal(data[i-1], data[i]))
			}
		}
	})
}
