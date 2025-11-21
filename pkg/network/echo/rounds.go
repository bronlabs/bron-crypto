package echo

import (
	"bytes"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

func (p *Participant[B]) Round1(message B) (network.OutgoingUnicasts[*Round1P2P], error) {
	serializedMessage, err := serde.MarshalCBOR(message)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal message")
	}

	r1 := hashmap.NewComparable[sharing.ID, *Round1P2P]()
	for id := range p.quorum.Iter() {
		if id == p.sharingId {
			continue
		}
		r1.Put(id, &Round1P2P{
			Payload: serializedMessage,
		})
	}

	p.state.messages[p.sharingId] = serializedMessage
	return r1.Freeze(), nil
}

func (p *Participant[B]) Round2(r1 network.RoundMessages[*Round1P2P]) (network.OutgoingUnicasts[*Round2P2P], error) {
	receivedMessages := make(map[sharing.ID][]byte)
	for id := range p.quorum.Iter() {
		if id == p.sharingId {
			continue
		}
		m, ok := r1.Get(id)
		if !ok {
			return nil, errs.NewFailed("missing message")
		}
		receivedMessages[id] = m.Payload
		p.state.messages[id] = m.Payload
	}

	r2 := hashmap.NewComparable[sharing.ID, *Round2P2P]()
	for id := range p.quorum.Iter() {
		if id == p.sharingId {
			continue
		}
		r2.Put(id, &Round2P2P{
			Echo: receivedMessages,
		})
	}

	return r2.Freeze(), nil
}

func (p *Participant[B]) Round3(r2 network.RoundMessages[*Round2P2P]) (network.RoundMessages[B], error) {
	received := make(map[sharing.ID][]byte)
	for id := range p.quorum.Iter() {
		if id == p.sharingId {
			continue
		}

		message := p.state.messages[id]
		for echoId := range p.quorum.Iter() {
			if echoId == p.sharingId || echoId == id {
				continue
			}
			echo, ok := r2.Get(echoId)
			if !ok {
				return nil, errs.NewFailed("missing message")
			}
			echoMessage := echo.Echo[id]
			if bytes.Compare(message, echoMessage) != 0 {
				return nil, errs.NewFailed("mismatched echo")
			}
		}
		received[id] = message
	}

	r3 := hashmap.NewComparable[sharing.ID, B]()
	for id := range p.quorum.Iter() {
		if id == p.sharingId {
			continue
		}
		message, err := serde.UnmarshalCBOR[B](received[id])
		if err != nil {
			return nil, errs.WrapSerialisation(err, "failed to unmarshal message")
		}
		r3.Put(id, message)
	}

	return r3.Freeze(), nil
}
