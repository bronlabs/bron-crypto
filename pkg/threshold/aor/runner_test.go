package aor_test

import (
	crand "crypto/rand"
	"io"
	"maps"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/aor"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestHappyPathRunner(t *testing.T) {
	t.Parallel()
	for i := range 128 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			testHappyPathRunner(t)
		})
	}
}

func testHappyPathRunner(t *testing.T) {
	t.Helper()

	const sampleLength = 32
	prng := crand.Reader
	ids := []sharing.ID{1, 2, 4, 6}
	quorum := hashset.NewComparable(ids...).Freeze()
	coordinator := testutils.NewMockCoordinator(ids...)
	tapes := make(map[sharing.ID]transcripts.Transcript)
	routers := make(map[sharing.ID]network.Router)
	samples := make(map[sharing.ID][]byte)
	samplesMutex := sync.Mutex{}
	for id := range quorum.Iter() {
		tapes[id] = hagrid.NewTranscript("test")
		routers[id] = coordinator.RouterFor(id)
	}

	runner := func(router network.Router, id sharing.ID, quorum network.Quorum, tape transcripts.Transcript, prng io.Reader) error {
		sample, err := aor.RunAgreeOnRandom(router, id, quorum, sampleLength, tape, prng)
		if err != nil {
			return err
		}

		samplesMutex.Lock()
		defer samplesMutex.Unlock()
		samples[id] = sample
		return nil
	}
	var errGroup errgroup.Group
	for _, id := range ids {
		errGroup.Go(func() error {
			return runner(routers[id], id, quorum, tapes[id], prng)
		})
	}
	err := errGroup.Wait()
	require.NoError(t, err)

	t.Run("should generate valid samples", func(t *testing.T) {
		t.Parallel()
		require.Len(t, samples, len(ids))
		s, ok := samples[ids[0]]
		require.True(t, ok)

		for _, id := range ids {
			si, ok := samples[id]
			require.True(t, ok)
			require.Equal(t, s, si)
			require.Len(t, si, sampleLength)
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
