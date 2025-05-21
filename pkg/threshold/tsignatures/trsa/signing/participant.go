package signing

import (
	"crypto"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

var (
	_ types.ThresholdSignatureParticipant = (*Cosigner)(nil)
)

type Cosigner struct {
	MyAuthKey types.AuthKey
	MyShard   *trsa.Shard
	Protocol  types.ThresholdProtocol
	H         crypto.Hash
}

func NewCosigner(authKey types.AuthKey, shard *trsa.Shard, protocol types.ThresholdProtocol, h crypto.Hash) *Cosigner {
	return &Cosigner{
		MyAuthKey: authKey,
		MyShard:   shard,
		Protocol:  protocol,
		H:         h,
	}
}

func (c *Cosigner) IdentityKey() types.IdentityKey {
	return c.MyAuthKey
}

func (c *Cosigner) SharingId() types.SharingID {
	return c.MyShard.D1Share.SharingId()
}

func (c *Cosigner) Quorum() ds.Set[types.IdentityKey] {
	return c.Protocol.Participants()
}
