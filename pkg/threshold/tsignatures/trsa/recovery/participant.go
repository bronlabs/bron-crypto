package recovery

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

var (
	_ types.ThresholdParticipant = (*Participant)(nil)
	_ types.ThresholdParticipant = (*Recoverer)(nil)
)

type Participant struct {
	MySharingId types.SharingID
	MyAuthKey   types.AuthKey
	Protocol    types.ThresholdProtocol
	SharingCfg  types.SharingConfig
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyAuthKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}

type Recoverer struct {
	Participant
	MyShard             *trsa.Shard
	MislayerSharingId   types.SharingID
	MislayerIdentityKey types.IdentityKey
}

func NewRecoverer(authKey types.AuthKey, protocol types.ThresholdProtocol, shard *trsa.Shard, mislayer types.IdentityKey) (*Recoverer, error) {
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	sharingId, ok := sharingCfg.Reverse().Get(authKey)
	if !ok {
		return nil, errs.NewFailed("invalid identity")
	}
	mislayerSharingId, ok := sharingCfg.Reverse().Get(mislayer)
	if !ok {
		return nil, errs.NewFailed("invalid identity")
	}

	p := &Recoverer{
		Participant: Participant{
			MySharingId: sharingId,
			MyAuthKey:   authKey,
			Protocol:    protocol,
			SharingCfg:  sharingCfg,
		},
		MyShard:             shard,
		MislayerSharingId:   mislayerSharingId,
		MislayerIdentityKey: mislayer,
	}

	return p, nil
}

type Mislayer struct {
	Participant
}

func NewMislayer(authKey types.AuthKey, protocol types.ThresholdProtocol) (*Mislayer, error) {
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	sharingId, ok := sharingCfg.Reverse().Get(authKey)
	if !ok {
		return nil, errs.NewFailed("invalid identity")
	}

	p := &Mislayer{
		Participant: Participant{
			MySharingId: sharingId,
			MyAuthKey:   authKey,
			Protocol:    protocol,
			SharingCfg:  sharingCfg,
		},
	}

	return p, nil
}
