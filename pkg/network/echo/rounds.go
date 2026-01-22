package echo

import (
	"bytes"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// Round1 broadcasts the sender's message to all other parties.
func (p *Participant[B]) Round1(message B) (network.OutgoingUnicasts[*Round1P2P], error) {
	serializedMessage, err := serde.MarshalCBOR(message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal message")
	}

	r1 := hashmap.NewComparable[sharing.ID, *Round1P2P]()
	for id := range p.quorum.Iter() {
		if id == p.sharingID {
			continue
		}
		r1.Put(id, &Round1P2P{
			Payload: serializedMessage,
		})
	}

	p.state.messages[p.sharingID] = serializedMessage
	return r1.Freeze(), nil
}

// Round2 echoes every received payload back to all parties.
func (p *Participant[B]) Round2(r1 network.RoundMessages[*Round1P2P]) (network.OutgoingUnicasts[*Round2P2P], error) {
	receivedMessages := make(map[sharing.ID][]byte)
	for id := range p.quorum.Iter() {
		if id == p.sharingID {
			continue
		}
		m, ok := r1.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message")
		}
		receivedMessages[id] = m.Payload
		p.state.messages[id] = m.Payload
	}

	r2 := hashmap.NewComparable[sharing.ID, *Round2P2P]()
	for id := range p.quorum.Iter() {
		if id == p.sharingID {
			continue
		}
		r2.Put(id, &Round2P2P{
			Echo: receivedMessages,
		})
	}

	return r2.Freeze(), nil
}

// Round3 validates echo consistency and outputs the agreed messages.
func (p *Participant[B]) Round3(r2 network.RoundMessages[*Round2P2P]) (network.RoundMessages[B], error) {
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
			echoMessage := echo.Echo[id]
			if !bytes.Equal(message, echoMessage) {
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
