package aor_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"maps"
	"slices"
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

func Test_Runner(t *testing.T) {
	t.Parallel()
	const sampleLength = 32

	for range 1 {
		prng := crand.Reader
		ids := []sharing.ID{1, 2, 4, 6}
		quorum := hashset.NewComparable(ids...).Freeze()
		coordinator := testutils.NewMockCoordinator(ids...)
		tapes := make(map[sharing.ID]transcripts.Transcript)
		routers := make(map[sharing.ID]testutils.Router)
		samples := make(map[sharing.ID][]byte)
		samplesMutex := sync.Mutex{}
		for id := range quorum.Iter() {
			tapes[id] = hagrid.NewTranscript("test")
			routers[id] = coordinator.RouterFor(id)
		}

		runner := func(router testutils.Router, id sharing.ID, quorum network.Quorum, tape transcripts.Transcript, prng io.Reader) error {
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

		require.Len(t, samples, len(ids))
		sample := slices.Collect(maps.Values(samples))[0]
		for _, id := range ids {
			require.True(t, bytes.Equal(samples[id], sample))
		}
	}
}
