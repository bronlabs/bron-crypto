package prob_prime

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_n"
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
	GammaDealer   *replicated.IntDealer
	MRError       int

	Prng  io.Reader
	Tape  transcripts.Transcript
	State State
}

type State struct {
	aShare       *replicated.IntShare
	bShare       *replicated.IntShare
	n            *big.Int
	v            *big.Int
	gammaShares  map[types.SharingID]*replicated.IntShare
	gammaMul     *mul_n.Participant
	gammaShare   *replicated.IntShare
	gammaAInvMul *mul_n.Participant
	yMul         *mul_n.Participant
	zMul         *mul_n.Participant

	zShare *replicated.IntShare
}

func NewParticipant(tape transcripts.Transcript, myIdentityKey types.IdentityKey, protocol types.ThresholdProtocol, n *big.Int, prng io.Reader) *Participant {
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, _ := sharingCfg.Reverse().Get(myIdentityKey)
	unqualifiedSets, err := replicated.BuildSortedMaxUnqualifiedSets(protocol.Threshold(), protocol.TotalParties())
	if err != nil {
		panic(err)
	}
	mrError := len(unqualifiedSets) + 1
	gammaDealer, err := replicated.NewIntDealer(protocol.Threshold(), protocol.TotalParties(), replicated.Modulus(n))
	if err != nil {
		panic(err)
	}

	return &Participant{
		MyIdentityKey: myIdentityKey,
		MySharingId:   mySharingId,
		Protocol:      protocol,
		SharingCfg:    sharingCfg,
		MRError:       mrError,
		GammaDealer:   gammaDealer,
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
