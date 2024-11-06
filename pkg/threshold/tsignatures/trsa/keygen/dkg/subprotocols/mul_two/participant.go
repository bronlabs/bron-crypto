package mul_two

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"io"
)

var (
	_ types.ThresholdParticipant = (*Participant)(nil)
)

type Participant struct {
	MyIdentityKey types.IdentityKey
	MySharingId   types.SharingID
	Protocol      types.ThresholdProtocol
	SharingCfg    types.SharingConfig
	MulTable      map[types.SharingID][]*replicated.SharingIdSetPair
	Dealer        *replicated.IntDealer
	Prng          io.Reader

	State State
}

type State struct {
	Result *replicated.IntShare
}

func NewParticipant(me types.IdentityKey, protocol types.ThresholdProtocol, prng io.Reader, sharingOpts ...replicated.SharingOpt) *Participant {
	if (2*protocol.Threshold() - 1) > protocol.TotalParties() {
		panic("invalid access structure")
	}

	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, _ := sharingCfg.Reverse().Get(me)
	mulTable, err := replicated.BuildMulTable(protocol.Threshold(), protocol.TotalParties())
	if err != nil {
		panic(err)
	}
	dealer, err := replicated.NewIntDealer(protocol.Threshold(), protocol.TotalParties(), sharingOpts...)
	if err != nil {
		panic(err)
	}

	return &Participant{
		MyIdentityKey: me,
		MySharingId:   mySharingId,
		Protocol:      protocol,
		SharingCfg:    sharingCfg,
		MulTable:      mulTable,
		Dealer:        dealer,
		Prng:          prng,
		State:         State{},
	}
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyIdentityKey
}
