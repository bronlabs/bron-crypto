package tsig

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type Shard[
	PK signatures.PublicKey[PK],
	S sharing.Share[S],
	AC sharing.AccessStructure,
] interface {
	Share() S
	PublicMaterial[PK, AC]
	base.Hashable[Shard[PK, S, AC]]
}

type PublicMaterial[
	PK signatures.PublicKey[PK],
	AC sharing.AccessStructure,
] interface {
	PublicKey() PK
	AccessStructure() AC
}

type Cosigner[
	PK signatures.PublicKey[PK],
	S sharing.Share[S],
	AC sharing.AccessStructure,
] interface {
	Shard() Shard[PK, S, AC]
	SessionID() network.SID
	SharingID() sharing.ID
	Quorum() network.Quorum
}

type Aggregator[
	PK signatures.PublicKey[PK],
	PS base.BytesLike,
	M signatures.Message,
	SG signatures.Signature[SG],
] interface {
	PublicMaterial() PublicMaterial[PK, sharing.AccessStructure]
	Aggregate(partialSignatures network.RoundMessages[PS], message M) (SG, error)
}
