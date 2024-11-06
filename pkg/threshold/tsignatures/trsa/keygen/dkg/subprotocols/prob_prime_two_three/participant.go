package prob_prime_two_three

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_two"
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

	Prng  io.Reader
	Tape  transcripts.Transcript
	State State
}

type State struct {
	aShare       *replicated.IntShare
	bShare       *replicated.IntShare
	n            *big.Int
	v            *big.Int
	gammaShares  []*replicated.IntShare
	gamma12Mul   *mul_two.Participant
	gamma123Mul  *mul_two.Participant
	gammaShare   *replicated.IntShare
	gammaAInvMul *mul_two.Participant
	yMul         *mul_two.Participant

	abMul                 *mul_two.Participant
	cdMul                 *mul_two.Participant
	efMul                 *mul_two.Participant
	ghMul                 *mul_two.Participant
	ijMul                 *mul_two.Participant
	klMul                 *mul_two.Participant
	mnMul                 *mul_two.Participant
	opMul                 *mul_two.Participant
	qrMul                 *mul_two.Participant
	abcdMul               *mul_two.Participant
	efghMul               *mul_two.Participant
	ijklMul               *mul_two.Participant
	mnopMul               *mul_two.Participant
	zQR                   *replicated.IntShare
	abcdefghMul           *mul_two.Participant
	ijklmnopMul           *mul_two.Participant
	abcdefghijklmnopMul   *mul_two.Participant
	abcdefghijklmnopqrMul *mul_two.Participant

	zShare *replicated.IntShare
}

func NewParticipant(tape transcripts.Transcript, myIdentityKey types.IdentityKey, protocol types.ThresholdProtocol, n *big.Int, prng io.Reader) *Participant {
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
		Prng:          prng,
		Tape:          tape,
		State:         State{n: n},
	}
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}
