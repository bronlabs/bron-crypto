package network

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// TODO: rename to fmt.Stringer
type Round = uint64

type RoundMessages[M Message] = ds.Map[sharing.ID, M]
type OutgoingUnicasts[M Message] = ds.Map[sharing.ID, M]
type Quorum = ds.Set[sharing.ID]
