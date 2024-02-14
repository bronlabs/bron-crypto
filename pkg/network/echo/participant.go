package echo

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ types.MPCParticipant = (*Participant)(nil)
var _ types.WithAuthKey = (*Participant)(nil)

type Participant struct {
	myAuthKey types.AuthKey
	sid       []byte

	Protocol types.MPCProtocol

	initiator types.IdentityKey
	round     int
	state     *State

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Participant) AuthKey() types.AuthKey {
	return p.myAuthKey
}

func (p *Participant) IsInitiator() bool {
	return p.IdentityKey().PublicKey().Equal(p.initiator.PublicKey())
}

type State struct {
	messageToBroadcast       []byte
	receivedBroadcastMessage []byte

	_ ds.Incomparable
}

func NewInitiator(uniqueSessionId []byte, authKey types.AuthKey, protocol types.MPCProtocol, message []byte) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, authKey, protocol, authKey); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct initiator")
	}
	result := &Participant{
		myAuthKey: authKey,
		Protocol:  protocol,
		initiator: authKey,
		sid:       uniqueSessionId,
		state: &State{
			messageToBroadcast: message,
		},
		round: 1,
	}
	if err := types.ValidateMPCProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}
	return result, nil
}

func NewResponder(uniqueSessionId []byte, authKey types.AuthKey, protocol types.MPCProtocol, initiator types.IdentityKey) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, authKey, protocol, initiator); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct responder")
	}
	result := &Participant{
		myAuthKey: authKey,
		initiator: initiator,
		sid:       uniqueSessionId,
		state:     &State{},
		Protocol:  protocol,
		round:     1,
	}
	if err := types.ValidateMPCProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}
	return result, nil
}

func validateInputs(uniqueSessionId []byte, authKey types.AuthKey, protocol types.MPCProtocol, initiator types.IdentityKey) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "identity key")
	}
	if err := types.ValidateMPCProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "cohort config is invalid")
	}
	if err := types.ValidateIdentityKey(initiator); err != nil {
		return errs.WrapValidation(err, "initator identity key")
	}
	if !protocol.Participants().Contains(initiator) {
		return errs.NewMissing("initator is not one of the participants")
	}
	if protocol.Participants().Size() <= 2 {
		return errs.NewSize("total participants (%d) <= 2", protocol.Participants().Size())
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewIsZero("sid length is zero")
	}
	return nil
}
