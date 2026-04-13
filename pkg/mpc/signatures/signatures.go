package signatures

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	normal_signatures "github.com/bronlabs/bron-crypto/pkg/signatures"
)

// Shard represents a signature shard held by a participant.
type Shard[
	PK normal_signatures.PublicKey[PK],
	S sharing.Share[S],
] interface {
	Share() S
	PublicMaterial[PK]
	base.Hashable[Shard[PK, S]]
}

// PublicMaterial represents the public material shared among participants.
type PublicMaterial[
	PK normal_signatures.PublicKey[PK],
] interface {
	PublicKey() PK
}
