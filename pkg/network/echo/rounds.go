package echo

import (
	"crypto/subtle"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

func (p *Participant) Round1() (network.RoundMessages[types.Protocol, *Round1P2P], error) {
	// Validation
	if p.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	result := network.NewRoundMessages[types.Protocol, *Round1P2P]()
	if p.IsInitiator() {
		for participant := range p.Protocol.Participants().Iter() {
			if participant.Equal(p.IdentityKey()) {
				continue
			}
			authMessage, err := hashing.HashPrefixedLength(base.RandomOracleHashFunction, p.SessionId, participant.PublicKey().ToAffineCompressed(), p.state.messageToBroadcast)
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

	p.Round++
	return result, nil
}

func (p *Participant) Round2(initiatorMessage *Round1P2P) (network.RoundMessages[types.Protocol, *Round2P2P], error) {
	// Validation
	if p.Round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if !p.IsInitiator() {
		if err := initiatorMessage.Validate(p.Protocol); err != nil {
			return nil, errs.WrapValidation(err, "Invalid round %d input messages", p.Round)
		}
	}

	result := network.NewRoundMessages[types.Protocol, *Round2P2P]()

	// step 2.1 initiator skips.
	if !p.IsInitiator() {
		for participant := range p.Protocol.Participants().Iter() {
			if participant.Equal(p.IdentityKey()) {
				continue
			}
			authMessage, err := hashing.HashPrefixedLength(base.RandomOracleHashFunction, p.SessionId, p.IdentityKey().PublicKey().ToAffineCompressed(), initiatorMessage.Message)
			if err != nil {
				return nil, errs.WrapHashing(err, "couldn't recompute auth message")
			}
			// step 2.2 responder verifies the signature.
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

	p.Round++
	return result, nil
}

func (p *Participant) Round3(p2pMessages network.RoundMessages[types.Protocol, *Round2P2P]) ([]byte, error) {
	// Validation
	if p.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.NonInitiatorParticipants(), p.IdentityKey(), p2pMessages); err != nil {
		return nil, errs.WrapValidation(err, "Invalid round %d input messages", p.Round)
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
	for sender, message := range p2pMessages.Iter() { // TODO: iter()
		// if it is initiator, we need to verify that all messages are the same.
		// if it is responder, we need to verify that the message is the same as the one we received from the initiator.
		if !p.IsInitiator() {
			authMessage, err := hashing.HashPrefixedLength(base.RandomOracleHashFunction, p.SessionId, sender.PublicKey().ToAffineCompressed(), messageToVerify)
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

	p.Round++
	return messageToVerify, nil
}
