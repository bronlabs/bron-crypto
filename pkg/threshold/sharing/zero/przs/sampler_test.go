package przs_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
	require.NoError(t, err)

	quorum := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
	tape := hagrid.NewTranscript("test")

	participants := make([]*przsSetup.Participant, quorum.Size())
	for i, sharingID := range quorum.Iter2() {
		participants[i], err = przsSetup.NewParticipant(sessionID, sharingID, quorum, tape.Clone(), prng)
		require.NoError(t, err)
	}

	r1bo := make(map[sharing.ID]*przsSetup.Round1Broadcast)
	for _, p := range participants {
		r1bo[p.SharingID()], err = p.Round1()
		require.NoError(t, err)
	}
	r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)

	r2uo := make(map[sharing.ID]network.RoundMessages[*przsSetup.Round2P2P])
	for _, p := range participants {
		r2uo[p.SharingID()], err = p.Round2(r2bi[p.SharingID()])
		require.NoError(t, err)
	}
	r3ui := ntu.MapUnicastO2I(t, participants, r2uo)

	seeds := make(map[sharing.ID]przs.Seeds)
	for _, p := range participants {
		seeds[p.SharingID()], err = p.Round3(r3ui[p.SharingID()])
		require.NoError(t, err)
	}

	field := k256.NewScalarField()
	samplers := make(map[sharing.ID]*przs.Sampler[*k256.Scalar])
	for i, s := range seeds {
		samplers[i], err = przs.NewSampler(i, quorum, s, field)
		require.NoError(t, err)
	}

	zero := field.Zero()
	for _, sampler := range samplers {
		sample, err := sampler.Sample()
		require.NoError(t, err)
		require.False(t, sample.IsZero())
		zero = zero.Add(sample)
	}
	require.True(t, zero.IsZero())
}
