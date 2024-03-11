package echo

import (
	"crypto/subtle"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

func (p *Participant) Round1() (network.RoundMessages[*Round1P2P], error) {
	// Validation
	if err := p.InRound(1); err != nil {
		return nil, errs.Forward(err)
	}

	result := network.NewRoundMessages[*Round1P2P]()
	if p.IsInitiator() {
		for participant := range p.Protocol().Participants().Iter() {
			if participant.Equal(p.IdentityKey()) {
				continue
			}
			authMessage, err := hashing.HashChain(base.RandomOracleHashFunction, p.SessionId(), participant.PublicKey().ToAffineCompressed(), p.state.messageToBroadcast)
			if err != nil {
				return nil, errs.WrapHashing(err, "couldn't produce auth message")
			}
			// step 1.1 and 1.2
			result.Put(participant, &Round1P2P{
				InitiatorSignature: p.AuthKey().Sign(authMessage),
				Message:            p.state.messageToBroadcast,
			})
		}
	}

	p.NextRound()
	return result, nil
}

func (p *Participant) Round2(initiatorMessage *Round1P2P) (network.RoundMessages[*Round2P2P], error) {
	// Validation
	if err := p.InRound(2); err != nil {
		return nil, errs.Forward(err)
	}
	if !p.IsInitiator() {
		if err := network.ValidateMessage(initiatorMessage); err != nil {
			return nil, errs.Forward(err)
		}
	}

	result := network.NewRoundMessages[*Round2P2P]()

	// step 2.1 if initiator
	if !p.IsInitiator() {
		for participant := range p.Protocol().Participants().Iter() {
			if participant.Equal(p.IdentityKey()) {
				continue
			}
			authMessage, err := hashing.HashChain(base.RandomOracleHashFunction, p.SessionId(), p.IdentityKey().PublicKey().ToAffineCompressed(), initiatorMessage.Message)
			if err != nil {
				return nil, errs.WrapHashing(err, "couldn't recompute auth message")
			}
			// step 2.2 if responder
			if err := p.initiator.Verify(initiatorMessage.InitiatorSignature, authMessage); err != nil {
				// step 2.3
				return nil, errs.NewIdentifiableAbort(p.initiator.String(), "failed to verify signature")
			}
			// step 2.4
			result.Put(participant, &Round2P2P{
				InitiatorSignature: initiatorMessage.InitiatorSignature,
				Message:            initiatorMessage.Message,
			})
			if p.state.receivedBroadcastMessage == nil {
				p.state.receivedBroadcastMessage = initiatorMessage.Message
			}
		}
	}

	p.NextRound()
	return result, nil
}

func (p *Participant) Round3(p2pMessages network.RoundMessages[*Round2P2P]) ([]byte, error) {
	// Validation
	if err := p.InRound(3); err != nil {
		return nil, errs.Forward(err)
	}
	if err := network.ValidateMessages(p.NonInitiatorParticipants(), p.IdentityKey(), p2pMessages); err != nil {
		return nil, errs.Forward(err)
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
	for pair := range p2pMessages.Iter() {
		sender := pair.Key
		message := pair.Value
		// if it is initiator, we need to verify that all messages are the same.
		// if it is responder, we need to verify that the message is the same as the one we received from the initiator.
		if !p.IsInitiator() {
			authMessage, err := hashing.HashChain(base.RandomOracleHashFunction, p.SessionId(), sender.PublicKey().ToAffineCompressed(), messageToVerify)
			if err != nil {
				return nil, errs.WrapHashing(err, "couldn't recompute auth message")
			}
			// Step 3.1
			if err := p.initiator.Verify(message.InitiatorSignature, authMessage); err != nil {
				return nil, errs.NewIdentifiableAbort(sender.String(), "failed to verify signature")
			}
		}

		// step 3.2 if initiator, step 3.3 if responder
		if subtle.ConstantTimeCompare(messageToVerify, message.Message) != 1 {
			return nil, errs.NewFailed("broadcast message mismatch")
		}
	}

	p.LastRound()
	return messageToVerify, nil
}
