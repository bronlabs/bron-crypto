package echo

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Participant struct {
	types.Participant[types.Protocol]

	initiator types.IdentityKey

	state *State

	_ ds.Incomparable
}

type State struct {
	messageToBroadcast       []byte
	receivedBroadcastMessage []byte

	_ ds.Incomparable
}

func (p *Participant) IsInitiator() bool {
	return p.IdentityKey().PublicKey().Equal(p.initiator.PublicKey())
}

func (p *Participant) SetMessageToBroadcast(message []byte) {
	p.state.messageToBroadcast = message
}

func (p *Participant) NonInitiatorParticipants() ds.Set[types.IdentityKey] {
	receivers := p.Protocol().Participants().Clone()
	receivers.Remove(p.initiator)
	return receivers
}

func NewInitiator(baseParticipant types.Participant[types.Protocol], message []byte) (*Participant, error) {
	initiator := &Participant{
		Participant: baseParticipant,
		initiator:   baseParticipant.AuthKey(),
		state: &State{
			messageToBroadcast: message,
		},
	}
	if err := initiator.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the initiator")
	}
	initiator.NextRound(1)
	return initiator, nil
}

func NewResponder(baseParticipant types.Participant[types.Protocol], initiator types.IdentityKey) (*Participant, error) {
	responder := &Participant{
		Participant: baseParticipant,
		initiator:   initiator,
		state:       &State{},
	}
	if err := responder.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the responder")
	}
	responder.NextRound(1) // Responder starts at round 1, but does nothing until round 2.
	return responder, nil
}

func (p *Participant) Validate() error {
	if p.Participant == nil {
		return errs.NewIsNil("base participant")
	}
	if err := p.Participant.Validate(); err != nil {
		return errs.WrapValidation(err, "identity key")
	}
	if len(p.SessionId()) == 0 {
		return errs.NewIsZero("sessionId length is zero")
	}
	if err := types.ValidateProtocol(p.Protocol()); err != nil {
		return errs.WrapValidation(err, "protocol is invalid")
	}
	if err := types.ValidateIdentityKey(p.initiator); err != nil {
		return errs.WrapValidation(err, "initator identity key")
	}
	if !p.Protocol().Participants().Contains(p.initiator) {
		return errs.NewMissing("initator is not one of the participants")
	}
	if p.Protocol().Participants().Size() <= 2 {
		return errs.NewSize("total participants (%d) <= 2", p.Protocol().Participants().Size())
	}
	return nil
}
