package aor_test

import (
	crand "crypto/rand"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/aor"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	var err error
	ids := []sharing.ID{1, 2, 4, 6}
	quorum := hashset.NewComparable(ids...).Freeze()
	prng := crand.Reader
	const sampleLength = 64

	tapes := make(map[sharing.ID]transcripts.Transcript)
	for id := range quorum.Iter() {
		tapes[id] = hagrid.NewTranscript("test")
	}

	participants := make([]*aor.Participant, len(ids))
	for i, id := range ids {
		participants[i], err = aor.NewParticipant(id, quorum, sampleLength, tapes[id], prng)
		require.NoError(t, err)
	}

	r1Out := make(map[sharing.ID]*aor.Round1Broadcast)
	for _, p := range participants {
		r1Out[p.SharingID()], err = p.Round1()
		require.NoError(t, err)
	}

	r2In := testutils.MapBroadcastO2I(t, participants, r1Out)
	r2Out := make(map[sharing.ID]*aor.Round2Broadcast)
	for _, p := range participants {
		r2Out[p.SharingID()], err = p.Round2(r2In[p.SharingID()])
		require.NoError(t, err)
	}

	r3In := testutils.MapBroadcastO2I(t, participants, r2Out)
	samples := make(map[sharing.ID][]byte)
	for _, p := range participants {
		samples[p.SharingID()], err = p.Round3(r3In[p.SharingID()])
		require.NoError(t, err)
	}

	t.Run("should generate valid samples", func(t *testing.T) {
		t.Parallel()
		samplesSlice := slices.Collect(maps.Values(samples))
		for i := 0; i < quorum.Size(); i++ {
			require.Len(t, samplesSlice[i], sampleLength)
			if i > 0 {
				require.True(t, slices.Equal(samplesSlice[i-1], samplesSlice[i]))
			}
		}
	})

	t.Run("should match transcripts", func(t *testing.T) {
		t.Parallel()
		tapeValues := make([][]byte, quorum.Size())
		for i, tape := range slices.Collect(maps.Values(tapes)) {
			tapeValues[i], err = tape.ExtractBytes("test", 32)
			require.NoError(t, err)
			if i > 0 {
				require.True(t, slices.Equal(tapeValues[i-1], tapeValues[i]))
			}
		}
	})
}
