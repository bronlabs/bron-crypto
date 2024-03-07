package echo

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	t "github.com/copperexchange/krypton-primitives/pkg/base/types"
	tp "github.com/copperexchange/krypton-primitives/pkg/base/types/party"
)

var _ t.MPCParticipant = (*Participant)(nil)
var _ t.WithAuthKey = (*Participant)(nil)

type Participant struct {
	tp.Party[t.MPCProtocol]

	initiator t.IdentityKey

	state *State

	_ ds.Incomparable
}

func (p *Participant) IsInitiator() bool {
	return p.IdentityKey().PublicKey().Equal(p.initiator.PublicKey())
}

func (p *Participant) NonInitiatorParticipants() ds.Set[t.IdentityKey] {
	receivers := p.Protocol().Participants().Clone()
	receivers.Remove(p.initiator)
	return receivers
}

type State struct {
	messageToBroadcast       []byte
	receivedBroadcastMessage []byte

	_ ds.Incomparable
}

func NewInitiator(party tp.Party[t.MPCProtocol], message []byte) (*Participant, error) {
	if err := validateInputs(party, party.AuthKey()); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct initiator")
	}
	result := &Participant{
		Party:     party,
		initiator: party.AuthKey(),
		state: &State{
			messageToBroadcast: message,
		},
	}
	return result, nil
}

func NewResponder(party tp.Party[t.MPCProtocol], initiator t.IdentityKey) (*Participant, error) {
	if err := validateInputs(party, initiator); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct responder")
	}
	result := &Participant{
		Party:     party,
		initiator: initiator,
		state:     &State{},
	}

	return result, nil
}

func validateInputs(party tp.Party[t.MPCProtocol], initiator t.IdentityKey) error {
	if len(party.SessionId()) == 0 {
		return errs.NewIsZero("sessionId length is zero")
	}
	if err := t.ValidateMPCProtocol(party, party.Protocol()); err != nil {
		return errs.WrapValidation(err, "could not construct the participant")
	}
	if err := t.ValidateIdentityKey(initiator); err != nil {
		return errs.WrapValidation(err, "initator identity key")
	}
	if !party.Protocol().Participants().Contains(initiator) {
		return errs.NewMissing("initator is not one of the participants")
	}
	if party.Protocol().Participants().Size() <= 2 {
		return errs.NewSize("total participants (%d) <= 2", party.Protocol().Participants().Size())
	}
	return nil
}
