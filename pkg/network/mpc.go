package network

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

type Round = uint64

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
