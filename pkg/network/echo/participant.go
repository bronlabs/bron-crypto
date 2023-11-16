package echo

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	cipherSuite   *integration.CipherSuite
	MyIdentityKey integration.IdentityKey
	MySharingId   int
	sid           []byte

	CohortConfig *integration.CohortConfig

	initiator integration.IdentityKey
	round     int
	state     *State

	_ types.Incomparable
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) GetSharingId() int {
	return p.MySharingId
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

type State struct {
	messageToBroadcast       []byte
	receivedBroadcastMessage []byte

	_ types.Incomparable
}

func NewInitiator(cipherSuite *integration.CipherSuite, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, sid, message []byte) (*Participant, error) {
	err := cipherSuite.Validate()
	if err != nil {
		return nil, errs.WrapFailed(err, "invalid cipher cipherSuite")
	}
	err = cohortConfig.Validate()
	if err != nil {
		return nil, errs.WrapFailed(err, "invalid cohort config")
	}
	if cohortConfig.Participants.Len() <= 2 {
		return nil, errs.NewInvalidArgument("cohort config has less than 3 participants")
	}
	if identityKey == nil {
		return nil, errs.NewInvalidArgument("identityKey is nil")
	}
	if message == nil {
		return nil, errs.NewInvalidArgument("message is nil")
	}
	if sid == nil {
		return nil, errs.NewIsNil("sid is nil")
	}
	result := &Participant{
		MyIdentityKey: identityKey,
		cipherSuite:   cipherSuite,
		initiator:     identityKey,
		sid:           sid,
		state: &State{
			messageToBroadcast: message,
		},
		CohortConfig: cohortConfig,
		round:        1,
	}
	_, _, result.MySharingId = integration.DeriveSharingIds(identityKey, result.CohortConfig.Participants)
	return result, nil
}

func NewResponder(cipherSuite *integration.CipherSuite, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, sid []byte, initiator integration.IdentityKey) (*Participant, error) {
	err := cipherSuite.Validate()
	if err != nil {
		return nil, errs.WrapFailed(err, "invalid cipher cipherSuite")
	}
	err = cohortConfig.Validate()
	if cohortConfig.Participants.Len() <= 2 {
		return nil, errs.NewInvalidArgument("cohort config has less than 3 participants")
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "invalid cohort config")
	}
	if identityKey == nil {
		return nil, errs.NewInvalidArgument("identityKey is nil")
	}
	if sid == nil {
		return nil, errs.NewIsNil("sid is nil")
	}
	result := &Participant{
		MyIdentityKey: identityKey,
		cipherSuite:   cipherSuite,
		initiator:     initiator,
		sid:           sid,
		state:         &State{},
		CohortConfig:  cohortConfig,
		round:         1,
	}
	_, _, result.MySharingId = integration.DeriveSharingIds(identityKey, result.CohortConfig.Participants)
	return result, nil
}

func (p *Participant) IsInitiator() bool {
	return p.MyIdentityKey.PublicKey().Equal(p.initiator.PublicKey())
}
