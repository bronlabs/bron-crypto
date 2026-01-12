package transcripts_tu

import (
	"encoding/hex"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

func MakeRandomTapes(tb testing.TB, prng io.Reader, quorum network.Quorum) map[sharing.ID]transcripts.Transcript {
	tb.Helper()

	var label [32]byte
	_, err := io.ReadFull(prng, label[:])
	require.NoError(tb, err)

	tapes := make(map[sharing.ID]transcripts.Transcript)
	for id := range quorum.Iter() {
		tape := hagrid.NewTranscript(hex.EncodeToString(label[:]))
		tapes[id] = tape
	}

	return tapes
}
