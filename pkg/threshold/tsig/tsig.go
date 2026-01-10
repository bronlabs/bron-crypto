package tsig

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// Shard represents a threshold signature shard held by a participant.
type Shard[
	PK signatures.PublicKey[PK],
	S sharing.Share[S],
	AC sharing.AccessStructure,
] interface {
	Share() S
	PublicMaterial[PK, AC]
	base.Hashable[Shard[PK, S, AC]]
}

// PublicMaterial represents the public material shared among participants.
type PublicMaterial[
	PK signatures.PublicKey[PK],
	AC sharing.AccessStructure,
] interface {
	PublicKey() PK
	AccessStructure() AC
}
