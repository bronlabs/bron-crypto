package echo

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ types.Participant = (*Participant)(nil)

type Participant struct {
	myAuthKey types.AuthKey
	Protocol  types.Protocol
	Round     int
	SessionId []byte

	initiator types.IdentityKey
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

func (p *Participant) NonInitiatorParticipants() ds.Set[types.IdentityKey] {
	receivers := p.Protocol.Participants().Clone()
	receivers.Remove(p.initiator)
	return receivers
}

type State struct {
	messageToBroadcast       []byte
	receivedBroadcastMessage []byte

	_ ds.Incomparable
}

func NewInitiator(sessionId []byte, authKey types.AuthKey, protocol types.Protocol, message []byte) (*Participant, error) {
	if err := validateInputs(sessionId, authKey, protocol, authKey); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct initiator")
	}
	result := &Participant{
		myAuthKey: authKey,
		Protocol:  protocol,
		Round:     1,
		SessionId: sessionId,
		initiator: authKey,
		state: &State{
			messageToBroadcast: message,
		},
	}
	if err := types.ValidateProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}
	return result, nil
}

func NewResponder(sessionId []byte, authKey types.AuthKey, protocol types.Protocol, initiator types.IdentityKey) (*Participant, error) {
	if err := validateInputs(sessionId, authKey, protocol, initiator); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct responder")
	}
	result := &Participant{
		myAuthKey: authKey,
		initiator: initiator,
		SessionId: sessionId,
		state:     &State{},
		Protocol:  protocol,
		Round:     1,
	}
	if err := types.ValidateProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}
	return result, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, protocol types.Protocol, initiator types.IdentityKey) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "identity key")
	}
	if err := types.ValidateProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
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
	if len(sessionId) == 0 {
		return errs.NewIsZero("sessionId length is zero")
	}
	if !curveutils.AllOfSameCurve(initiator.PublicKey().Curve(), initiator.PublicKey(), authKey.PublicKey()) {
		return errs.NewCurve("authKey and initiator have different curves")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(initiator.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("not all participants have the same curve")
	}
	return nil
}
