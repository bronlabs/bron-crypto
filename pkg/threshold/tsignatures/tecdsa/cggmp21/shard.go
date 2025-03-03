package cggmp21

import (
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
)

type Shard struct {
	Share              *tsignatures.SigningKeyShare
	PaillierSecretKey  *paillier.SecretKey
	PublicShares       *tsignatures.PartialPublicKeys
	PaillierPublicKeys ds.Map[types.SharingID, *paillier.PublicKey]
}
