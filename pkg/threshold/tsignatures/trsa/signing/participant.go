package signing

import (
	"crypto"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
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

func NewCosigner(authKey types.AuthKey, shard *trsa.Shard, protocol types.ThresholdProtocol, h crypto.Hash) (*Cosigner, error) {
	if authKey == nil || shard == nil || protocol == nil || !h.Available() {
		return nil, errs.NewIsNil("argument")
	}
	if protocol.Threshold() != 2 || protocol.TotalParties() != 3 {
		return nil, errs.NewValidation("unsupported protocol")
	}

	p := &Cosigner{
		MyAuthKey: authKey,
		MyShard:   shard,
		Protocol:  protocol,
		H:         h,
	}
	if err := types.ValidateThresholdProtocol(p, protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid protocol")
	}

	return p, nil
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
