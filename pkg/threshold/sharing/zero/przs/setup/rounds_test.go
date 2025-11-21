package przsSetup_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(t, err)

	quorum := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
	tape := hagrid.NewTranscript("test")

	participants := make([]*przsSetup.Participant, quorum.Size())
	for i, sharingId := range quorum.Iter2() {
		participants[i], err = przsSetup.NewParticipant(sessionId, sharingId, quorum, tape.Clone(), prng)
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

	for i1 := range quorum.Iter() {
		for i2 := range quorum.Iter() {
			if i1 == i2 {
				continue
			}

			s1, ok := seeds[i1]
			require.True(t, ok)
			s2, ok := seeds[i2]
			require.True(t, ok)
			v1, ok := s1.Get(i2)
			require.True(t, ok)
			v2, ok := s2.Get(i1)
			require.True(t, ok)

			require.Equal(t, v1, v2)
		}
	}
}
