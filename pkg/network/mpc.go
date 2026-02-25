package network

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Round is the sequential identifier of a protocol step.
type Round = uint64

// RoundMessages maps sender IDs to their round messages.
type RoundMessages[M Message] = ds.Map[sharing.ID, M]

// OutgoingUnicasts maps recipients to outbound unicast payloads.
type OutgoingUnicasts[M Message] = ds.Map[sharing.ID, M]

// Quorum is the set of parties participating in a session.
type Quorum = ds.Set[sharing.ID]
