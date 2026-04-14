package echo

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1 broadcasts the sender's message to all other parties.
func (p *Participant[B, BP]) Round1(message B) (network.OutgoingUnicasts[*Round1P2P[B, BP], *Participant[B, BP]], error) {
	serializedMessage, err := serde.MarshalCBOR(message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal message")
	}

	r1 := hashmap.NewComparable[sharing.ID, *Round1P2P[B, BP]]()
	for id := range p.quorum.Iter() {
		if id == p.sharingID {
			continue
		}
		r1.Put(id, &Round1P2P[B, BP]{
			Payload: serializedMessage,
		})
	}

	p.state.messages[p.sharingID] = serializedMessage
	return r1.Freeze(), nil
}

// Round2 echoes every received payload back to all parties.
func (p *Participant[B, BP]) Round2(r1 network.RoundMessages[*Round1P2P[B, BP], *Participant[B, BP]]) (network.OutgoingUnicasts[*Round2P2P[B, BP], *Participant[B, BP]], error) {
	receivedMessages := make(map[sharing.ID][]byte)
	for id := range p.quorum.Iter() {
		if id == p.sharingID {
			continue
		}
		m, ok := r1.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message")
		}
		if err := m.Validate(p, id); err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to validate round 1 message")
		}
		receivedMessages[id] = m.Payload
		p.state.messages[id] = m.Payload
	}

	r2 := hashmap.NewComparable[sharing.ID, *Round2P2P[B, BP]]()
	for id := range p.quorum.Iter() {
		if id == p.sharingID {
			continue
		}
		r2.Put(id, &Round2P2P[B, BP]{
			Echo: receivedMessages,
		})
	}

	return r2.Freeze(), nil
}

// Round3 validates echo consistency and outputs the agreed messages.
func (p *Participant[B, BP]) Round3(r2 network.RoundMessages[*Round2P2P[B, BP], *Participant[B, BP]]) (network.RoundMessages[B, BP], error) {
	received := make(map[sharing.ID][]byte)
	for id := range p.quorum.Iter() {
		if id == p.sharingID {
			continue
		}

		message := p.state.messages[id]
		for echoID := range p.quorum.Iter() {
			if echoID == p.sharingID || echoID == id {
				continue
			}
			echo, ok := r2.Get(echoID)
			if !ok {
				return nil, ErrFailed.WithMessage("missing message")
			}
			if err := echo.Validate(p, echoID); err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to validate round 2 message")
			}
			echoMessage := echo.Echo[id]
			_, isEq, _ := ct.CompareBytes(message, echoMessage)
			if isEq != ct.True {
				return nil, ErrFailed.WithMessage("mismatched echo")
			}
		}
		received[id] = message
	}

	r3 := hashmap.NewComparable[sharing.ID, B]()
	for id := range p.quorum.Iter() {
		if id == p.sharingID {
			continue
		}
		message, err := serde.UnmarshalCBOR[B](received[id])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to unmarshal message")
		}
		r3.Put(id, message)
	}

	return r3.Freeze(), nil
}
