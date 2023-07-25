package integration

import (
	"encoding/hex"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
)

type PresentParticipantSet struct {
	participants map[string]IdentityKey
}

func NewPresentParticipantSet(participants []IdentityKey) (PresentParticipantSet, error) {
	participantMap := map[string]IdentityKey{}
	for i, participant := range participants {
		if participant == nil {
			return PresentParticipantSet{}, errs.NewIsNil("participant %d is nil", i)
		}
		pubkeyHex := hex.EncodeToString(participant.PublicKey().ToAffineCompressed())
		if _, exists := participantMap[pubkeyHex]; exists {
			return PresentParticipantSet{}, errs.NewDuplicate("participant %d is duplicate", i)
		}
		participantMap[pubkeyHex] = participant
	}
	if len(participantMap) != len(participants) {
		return PresentParticipantSet{}, errs.NewInvalidArgument("not all participants are added")
	}
	return PresentParticipantSet{
		participants: participantMap,
	}, nil
}

func (p *PresentParticipantSet) Exist(identityKey IdentityKey) bool {
	pubkeyHex := hex.EncodeToString(identityKey.PublicKey().ToAffineCompressed())
	_, exists := p.participants[pubkeyHex]
	return exists
}

func (p *PresentParticipantSet) Size() int {
	return len(p.participants)
}
