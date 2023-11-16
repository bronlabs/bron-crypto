package echo

import (
	"crypto/subtle"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

type Round1P2P struct {
	// InitiatorSignature is signature of Message. We use this to authenticate that the message is sent by the initiator.
	InitiatorSignature []byte
	Message            []byte

	_ types.Incomparable
}
type Round2P2P struct {
	InitiatorSignature []byte
	Message            []byte

	_ types.Incomparable
}

// step 1.X.
func (p *Participant) Round1() (map[types.IdentityHash]*Round1P2P, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}
	p.round++
	var result = make(map[types.IdentityHash]*Round1P2P)
	if p.IsInitiator() {
		for _, participant := range p.CohortConfig.Participants.Iter() {
			if participant.PublicKey().Equal(p.MyIdentityKey.PublicKey()) {
				continue
			}
			var authMessage []byte
			authMessage = append(authMessage, p.sid...)
			authMessage = append(authMessage, participant.PublicKey().ToAffineCompressed()...)
			authMessage = append(authMessage, p.state.messageToBroadcast...)
			// step 1.1 and 1.2
			result[participant.Hash()] = &Round1P2P{
				InitiatorSignature: p.MyIdentityKey.Sign(authMessage),
				Message:            p.state.messageToBroadcast,
			}
		}
	}
	return result, nil
}

// step 2.X.
func (p *Participant) Round2(p2pMessage *Round1P2P) (map[types.IdentityHash]*Round2P2P, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	var result = make(map[types.IdentityHash]*Round2P2P, p.CohortConfig.Participants.Len())
	// step 2.1 if initiator
	if !p.IsInitiator() {
		if p2pMessage == nil {
			return nil, errs.NewInvalidRound("p2pMessages is nil")
		}

		for _, participant := range p.CohortConfig.Participants.Iter() {
			if participant.PublicKey().Equal(p.MyIdentityKey.PublicKey()) {
				continue
			}
			var authMessage []byte
			authMessage = append(authMessage, p.sid...)
			authMessage = append(authMessage, p.MyIdentityKey.PublicKey().ToAffineCompressed()...)
			authMessage = append(authMessage, p2pMessage.Message...)
			// step 2.2 if responder
			err := p.initiator.Verify(p2pMessage.InitiatorSignature, p.initiator.PublicKey(), authMessage)
			if err != nil {
				// step 2.3
				return nil, errs.NewIdentifiableAbort(p.initiator.Hash(), "failed to verify signature")
			}
			// step 2.4
			result[participant.Hash()] = &Round2P2P{
				InitiatorSignature: p2pMessage.InitiatorSignature,
				Message:            p2pMessage.Message,
			}
			if p.state.receivedBroadcastMessage == nil {
				p.state.receivedBroadcastMessage = p2pMessage.Message
			}
		}
	}
	p.round++
	return result, nil
}

// step 3.X.
func (p *Participant) Round3(p2pMessages map[types.IdentityHash]*Round2P2P) ([]byte, error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	var messageToVerify []byte
	if p.IsInitiator() {
		messageToVerify = p.state.messageToBroadcast
	} else {
		messageToVerify = p.state.receivedBroadcastMessage
	}
	if messageToVerify == nil {
		return nil, errs.NewFailed("messageToVerify is nil")
	}
	for participantHash, message := range p2pMessages {
		if message == nil {
			return nil, errs.NewIsNil("p2pMessages contains nil message")
		}

		// if it is initiator, we need to verify that all messages are the same.
		// if it is responder, we need to verify that the message is the same as the one we received from the initiator.
		if !p.IsInitiator() {
			var sender integration.IdentityKey
			for _, participant := range p.CohortConfig.Participants.Iter() {
				if participant.Hash() == participantHash {
					sender = participant
					break
				}
			}
			if sender == nil {
				return nil, errs.NewFailed("sender not found")
			}

			var authMessage []byte
			authMessage = append(authMessage, p.sid...)
			authMessage = append(authMessage, sender.PublicKey().ToAffineCompressed()...)
			authMessage = append(authMessage, message.Message...)
			// Step 3.1
			err := p.initiator.Verify(message.InitiatorSignature, p.initiator.PublicKey(), authMessage)
			if err != nil {
				return nil, errs.NewIdentifiableAbort(sender.Hash(), "failed to verify signature")
			}
		}

		// step 3.2 if initiator, step 3.3 if responder
		if subtle.ConstantTimeCompare(messageToVerify, message.Message) != 1 {
			return nil, errs.NewFailed("broadcast message mismatch")
		}
	}
	p.round++
	return messageToVerify, nil
}
