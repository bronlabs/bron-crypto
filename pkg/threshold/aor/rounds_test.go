package aor_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/aor"
	tu "github.com/bronlabs/bron-crypto/pkg/threshold/aor/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	ttu "github.com/bronlabs/bron-crypto/pkg/transcripts/testutils"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const total = 4
	const sampleLength = 64

	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, total)
	tapes := ttu.MakeRandomTapes(t, prng, quorum)
	participants := slices.Collect(maps.Values(tu.MakeAgreeOnRandomParticipants(t, quorum, tapes, sampleLength)))

	var err error
	r1Out := make(map[sharing.ID]*aor.Round1Broadcast)
	for _, p := range participants {
		r1Out[p.SharingID()], err = p.Round1()
		require.NoError(t, err)
	}

	r2In := ntu.MapBroadcastO2I(t, participants, r1Out)
	r2Out := make(map[sharing.ID]*aor.Round2Broadcast)
	for _, p := range participants {
		r2Out[p.SharingID()], err = p.Round2(r2In[p.SharingID()])
		require.NoError(t, err)
	}

	r3In := ntu.MapBroadcastO2I(t, participants, r2Out)
	samples := make(map[sharing.ID][]byte)
	for _, p := range participants {
		samples[p.SharingID()], err = p.Round3(r3In[p.SharingID()])
		require.NoError(t, err)
	}

	t.Run("should generate valid samples", func(t *testing.T) {
		t.Parallel()
		samplesSlice := slices.Collect(maps.Values(samples))
		for i := range quorum.Size() {
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
