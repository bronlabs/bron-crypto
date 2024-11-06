package sieve

import (
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
	PrimeDealer   *replicated.IntDealer
	Prng          io.Reader
	State         State
}

type State struct {
	pShare *replicated.IntShare
	qShare *replicated.IntShare
	pqMul  *mul_two.Participant
	nShare *replicated.IntShare
}

func NewParticipant(tape transcripts.Transcript, myIdentityKey types.IdentityKey, protocol types.ThresholdProtocol, primeBitLen uint, prng io.Reader) *Participant {
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, _ := sharingCfg.Reverse().Get(myIdentityKey)
	dealer, err := replicated.NewIntDealer(protocol.Threshold(), protocol.TotalParties(), replicated.BitLen(primeBitLen), replicated.SpecialForm(true))
	if err != nil {
		panic(err)
	}

	return &Participant{
		MyIdentityKey: myIdentityKey,
		MySharingId:   mySharingId,
		SharingCfg:    sharingCfg,
		Protocol:      protocol,
		Tape:          tape,
		PrimeDealer:   dealer,
		Prng:          prng,
		State:         State{},
	}
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}
