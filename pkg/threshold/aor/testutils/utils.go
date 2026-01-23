package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/aor"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/stretchr/testify/require"
)

func MakeAgreeOnRandomParticipants(tb testing.TB, quorum network.Quorum, tapes map[sharing.ID]transcripts.Transcript, sampleSize int) map[sharing.ID]*aor.Participant {
	tb.Helper()

	participants := map[sharing.ID]*aor.Participant{}
	for id := range quorum.Iter() {
		p, err := aor.NewParticipant(id, quorum, sampleSize, tapes[id], pcg.NewRandomised())
		require.NoError(tb, err)
		participants[id] = p
	}
	return participants
}

func MakeAgreeOnRandomRunners(tb testing.TB, quorum network.Quorum, tapes map[sharing.ID]transcripts.Transcript, sampleSize int) map[sharing.ID]network.Runner[[]byte] {
	tb.Helper()

	runners := map[sharing.ID]network.Runner[[]byte]{}
	for id := range quorum.Iter() {
		runner, err := aor.NewAgreeOnRandomRunner(id, quorum, sampleSize, tapes[id], pcg.NewRandomised())
		require.NoError(tb, err)
		runners[id] = runner
	}

	return runners
}
