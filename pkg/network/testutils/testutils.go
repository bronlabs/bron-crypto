package ntu

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/stretchr/testify/require"
)

// TestParticipant is the minimal interface needed to route messages in helpers.
type TestParticipant interface {
	SharingID() sharing.ID
}

// MakeRandomQuorum samples a random quorum of distinct non-zero sharing IDs.
func MakeRandomQuorum(tb testing.TB, prng io.Reader, n int) network.Quorum {
	tb.Helper()

	quorum := hashset.NewComparable[sharing.ID]()
	for quorum.Size() < n {
		var id [2]byte
		_, err := io.ReadFull(prng, id[:])
		require.NoError(tb, err)
		sharingID := binary.LittleEndian.Uint16(id[:])
		if sharingID != 0 {
			quorum.Add(sharing.ID(sharingID))
		}
	}

	return quorum.Freeze()
}

// MakeRandomSessionID reads 32 random bytes into an SID.
func MakeRandomSessionID(tb testing.TB, prng io.Reader) network.SID {
	tb.Helper()

	var sid network.SID
	_, err := io.ReadFull(prng, sid[:])
	require.NoError(tb, err)

	return sid
}

// MapO2I maps the outputs of all participants in a round of a protocol to the inputs of the next round
// with serialising and deserializing them throughout the process.
func MapO2I[
	P TestParticipant, BcastT, UnicastT network.Message[P],
](
	tb testing.TB,
	participants []P,
	broadcastOutputs map[sharing.ID]BcastT,
	UnicastOutputs map[sharing.ID]network.RoundMessages[UnicastT, P],
) (
	broadcastInputs map[sharing.ID]network.RoundMessages[BcastT, P],
	UnicastInputs map[sharing.ID]network.RoundMessages[UnicastT, P],
) {
	tb.Helper()
	if len(broadcastOutputs) != 0 {
		broadcastInputs = MapBroadcastO2I(tb, participants, broadcastOutputs)
	}
	if len(UnicastOutputs) != 0 {
		UnicastInputs = MapUnicastO2I(tb, participants, UnicastOutputs)
	}
	return broadcastInputs, UnicastInputs
}

// MapBroadcastO2I maps the broadcasts of all participants in a round of a protocol to the inputs of the next round
// with serialising and deserializing them throughout the process.
func MapBroadcastO2I[
	P interface {
		SharingID() sharing.ID
	}, BcastT network.Message[P],
](
	tb testing.TB,
	participants []P,
	broadcastOutputs map[sharing.ID]BcastT,
) (
	broadcastInputs map[sharing.ID]network.RoundMessages[BcastT, P],
) {
	tb.Helper()
	broadcastInputs = make(map[sharing.ID]network.RoundMessages[BcastT, P], len(participants))
	for _, receiver := range participants {
		inputs := hashmap.NewComparable[sharing.ID, BcastT]()
		for senderID, msg := range broadcastOutputs {
			if senderID == receiver.SharingID() {
				continue
			}
			if !utils.IsNil(msg) {
				inputs.Put(senderID, CBORRoundTrip(tb, msg))
			}
		}
		broadcastInputs[receiver.SharingID()] = inputs.Freeze()
	}
	return broadcastInputs
}

// MapUnicastO2I maps the P2P messages of all participants in a round of a protocol to the inputs of the next round
// with serialising and deserializing them throughout the process.
func MapUnicastO2I[
	P interface {
		SharingID() sharing.ID
	}, UnicastT network.Message[P],
](
	tb testing.TB,
	participants []P,
	p2pOutputs map[sharing.ID]network.RoundMessages[UnicastT, P],
) (
	p2pInputs map[sharing.ID]network.RoundMessages[UnicastT, P],
) {
	tb.Helper()
	p2pInputs = make(map[sharing.ID]network.RoundMessages[UnicastT, P])

	for _, receiver := range participants {
		inputs := hashmap.NewComparable[sharing.ID, UnicastT]()
		for senderID, messages := range p2pOutputs {
			if senderID == receiver.SharingID() {
				continue
			}
			if messages != nil {
				msg, ok := messages.Get(receiver.SharingID())
				if ok {
					inputs.Put(senderID, CBORRoundTrip(tb, msg))
				}
			}
		}
		p2pInputs[receiver.SharingID()] = inputs.Freeze()
	}
	return p2pInputs
}
