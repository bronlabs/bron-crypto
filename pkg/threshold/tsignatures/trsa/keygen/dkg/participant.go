package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/inv_mod"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/prob_prime_two_three"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/sieve"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"io"
	"math/big"
)

var (
	_ types.ThresholdParticipant = (*Participant)(nil)
)

type Participant struct {
	MyIdentityKey types.IdentityKey
	MySharingId   types.SharingID
	Protocol      types.ThresholdProtocol
	SharingCfg    types.SharingConfig
	Tape          transcripts.Transcript
	PrimeBitLen   uint
	Prng          io.Reader

	State State
}

type State struct {
	// subprotocol
	Sieve      *sieve.Participant
	ProbPrimeP *prob_prime_two_three.Participant
	ProbPrimeQ *prob_prime_two_three.Participant
	InvMod     *inv_mod.Participant

	pShare   *replicated.IntShare
	qShare   *replicated.IntShare
	n        *big.Int
	phiShare *replicated.IntShare
	dShare   *replicated.IntShare
}

func NewParticipant(tape transcripts.Transcript, myIdentityKey types.IdentityKey, protocol types.ThresholdProtocol, primeBitLen uint, prng io.Reader) *Participant {
	if protocol.Threshold() != 2 || protocol.TotalParties() != 3 {
		panic("invalid access structure")
	}
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, _ := sharingCfg.Reverse().Get(myIdentityKey)

	return &Participant{
		MyIdentityKey: myIdentityKey,
		MySharingId:   mySharingId,
		Protocol:      protocol,
		SharingCfg:    sharingCfg,
		Tape:          tape,
		PrimeBitLen:   primeBitLen,
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
