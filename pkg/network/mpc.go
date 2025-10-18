package network

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// TODO: rename to fmt.Stringer
type Round = uint64

// TODO: remove
type Party interface {
	Node
	ProtocolName() string
	Transcript() ts.Transcript
	SharingID() sharing.ID
	Round() Round
}

type RoundMessages[M Message] = ds.Map[sharing.ID, M]
type OutgoingUnicasts[M Message] ds.Map[sharing.ID, M]
type Quorum = ds.Set[sharing.ID]
