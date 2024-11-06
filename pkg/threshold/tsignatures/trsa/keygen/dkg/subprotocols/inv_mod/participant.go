package inv_mod

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_two"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"io"
)

var (
	_ types.ThresholdParticipant = (*Participant)(nil)
)

type Participant struct {
	MyIdentityKey types.IdentityKey
	MySharingId   types.SharingID
	SharingCfg    types.SharingConfig
	Protocol      types.ThresholdProtocol
	Tape          transcripts.Transcript
	Dealer        *replicated.IntDealer
	PrimeLen      uint
	Prng          io.Reader

	State State
}

type State struct {
	e              uint
	lambdaShare    *replicated.IntShare
	lambdaPhiMul   *mul_two.Participant
	lambdaPhiShare *replicated.IntShare
	rShare         *replicated.IntShare
	gammaShare     *replicated.IntShare
}

func NewParticipant(tape transcripts.Transcript, myIdentityKey types.IdentityKey, protocol types.ThresholdProtocol, primeLen uint, prng io.Reader) *Participant {
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, _ := sharingCfg.Reverse().Get(myIdentityKey)
	dealer, err := replicated.NewIntDealer(protocol.Threshold(), protocol.TotalParties(), replicated.BitLen(primeLen*4+base.ComputationalSecurity*2))
	if err != nil {
		panic(err)
	}

	return &Participant{
		MyIdentityKey: myIdentityKey,
		MySharingId:   mySharingId,
		SharingCfg:    sharingCfg,
		PrimeLen:      primeLen,
		Protocol:      protocol,
		Tape:          tape,
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
