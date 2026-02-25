package tsig

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
)

// Shard represents a threshold signature shard held by a participant.
type Shard[
	PK signatures.PublicKey[PK],
	S sharing.Share[S],
	AC accessstructures.Monotone,
] interface {
	Share() S
	PublicMaterial[PK, AC]
	base.Hashable[Shard[PK, S, AC]]
}

// PublicMaterial represents the public material shared among participants.
type PublicMaterial[
	PK signatures.PublicKey[PK],
	AC accessstructures.Monotone,
] interface {
	PublicKey() PK
	AccessStructure() AC
}
