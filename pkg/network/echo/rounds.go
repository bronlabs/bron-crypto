package echo

import (
	"crypto/subtle"

	"golang.org/x/crypto/sha3"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

type Round1P2P struct {
	// InitiatorSignature is signature of Message. We use this to authenticate that the message is sent by the initiator.
	InitiatorSignature []byte
	Message            []byte

	_ ds.Incomparable
}
type Round2P2P struct {
	InitiatorSignature []byte
	Message            []byte

	_ ds.Incomparable
}

// step 1.X.
func (p *Participant) Round1() (types.RoundMessages[*Round1P2P], error) {
	if p.round != 1 {
		return nil, errs.NewRound("round mismatch %d != 1", p.round)
	}
	result := types.NewRoundMessages[*Round1P2P]()
	if p.IsInitiator() {
		for participant := range p.Protocol.Participants().Iter() {
			if participant.Equal(p.IdentityKey()) {
				continue
			}
			authMessage, err := hashing.HashChain(sha3.New256, p.sid, participant.PublicKey().ToAffineCompressed(), p.state.messageToBroadcast)
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
	p.round++
	return result, nil
}

// step 2.X.
func (p *Participant) Round2(initiatorMessage *Round1P2P) (types.RoundMessages[*Round2P2P], error) {
	if p.round != 2 {
		return nil, errs.NewRound("round mismatch %d != 2", p.round)
	}
	result := types.NewRoundMessages[*Round2P2P]()
	// step 2.1 if initiator
	if !p.IsInitiator() {
		if initiatorMessage == nil {
			return nil, errs.NewRound("p2pMessages is nil")
		}

		for participant := range p.Protocol.Participants().Iter() {
			if participant.Equal(p.IdentityKey()) {
				continue
			}
			authMessage, err := hashing.HashChain(sha3.New256, p.sid, p.IdentityKey().PublicKey().ToAffineCompressed(), initiatorMessage.Message)
			if err != nil {
				return nil, errs.WrapHashing(err, "couldn't recompute auth message")
			}
			// step 2.2 if responder
			if err := p.initiator.Verify(initiatorMessage.InitiatorSignature, authMessage); err != nil {
				// step 2.3
				return nil, errs.NewIdentifiableAbort(p.initiator.PublicKey().ToAffineCompressed(), "failed to verify signature")
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
	p.round++
	return result, nil
}

// step 3.X.
func (p *Participant) Round3(p2pMessages types.RoundMessages[*Round2P2P]) ([]byte, error) {
	if p.round != 3 {
		return nil, errs.NewRound("round mismatch %d != 3", p.round)
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
		if message == nil {
			return nil, errs.NewIsNil("p2pMessages contains nil message")
		}

		// if it is initiator, we need to verify that all messages are the same.
		// if it is responder, we need to verify that the message is the same as the one we received from the initiator.
		if !p.IsInitiator() {
			if sender == nil {
				return nil, errs.NewFailed("sender not found")
			}

			authMessage, err := hashing.HashChain(sha3.New256, p.sid, sender.PublicKey().ToAffineCompressed(), messageToVerify)
			if err != nil {
				return nil, errs.WrapHashing(err, "couldn't recompute auth message")
			}
			// Step 3.1
			if err := p.initiator.Verify(message.InitiatorSignature, authMessage); err != nil {
				return nil, errs.NewIdentifiableAbort(sender.PublicKey().ToAffineCompressed(), "failed to verify signature")
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
