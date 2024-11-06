package dist_sieve

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_n"
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
	SharingCfg    types.SharingConfig
	Protocol      types.ThresholdProtocol
	Tape          transcripts.Transcript
	ExpTable      map[types.SharingID][]replicated.SharingIdSet
	PrimeBitLen   uint
	MB            *big.Int
	Prng          io.Reader
	State         State
}

type State struct {
	aShares      map[types.SharingID]*replicated.IntShare
	aMul         *mul_n.Participant
	aModFour     uint
	bShare       *replicated.IntShare
	pShare       *replicated.IntShare
	pShareAdjust uint
	pqMul        *mul_two.Participant
	nShare       *replicated.IntShare
}

func NewParticipant(tape transcripts.Transcript, myIdentityKey types.IdentityKey, protocol types.ThresholdProtocol, primeBitLen uint, prng io.Reader) *Participant {
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, _ := sharingCfg.Reverse().Get(myIdentityKey)
	mb := big.NewInt(2)
	for i := int64(3); i <= 65536; i += 2 {
		theEye := big.NewInt(i)
		if theEye.ProbablyPrime(0) {
			mb.Mul(mb, theEye)
			if mb.BitLen() > (int(primeBitLen) - 128) { // 64 is a good compromise
				break
			}
		}
	}
	expTable, err := replicated.BuildExpTable(protocol.Threshold(), protocol.TotalParties())
	if err != nil {
		panic(err)
	}

	return &Participant{
		MyIdentityKey: myIdentityKey,
		MySharingId:   mySharingId,
		SharingCfg:    sharingCfg,
		MB:            mb,
		Protocol:      protocol,
		ExpTable:      expTable,
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
