package broadcast

import (
	"bytes"
	crand "crypto/rand"
	"encoding/gob"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	echo2 "github.com/copperexchange/krypton-primitives/pkg/network/echo"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/auth"
)

var (
	_ Client = (*broadcastClientImpl)(nil)
)

type messageId [16]byte
type messageType string

const (
	bcastType messageType = "bcast"
	echoType  messageType = "echo"
	p2pType   messageType = "p2p"
)

type message struct {
	Id      messageId
	Type    messageType
	Payload []byte
}

type broadcastClientImpl struct {
	id            types.AuthKey
	downstream    auth.Client
	protocol      types.Protocol
	senders       map[messageId]*echo2.Participant
	responders    map[messageId]*echo2.Participant
	messageBuffer map[messageId]network.RoundMessages[types.Protocol, *echo2.Round2P2P]

	outgoingBroadcast chan *exchange
	incomingBroadcast chan *exchange

	outgoingUnicast chan *exchange
	incomingUnicast chan *exchange
}

func (c *broadcastClientImpl) SendTo(to types.IdentityKey, payload []byte) {
	c.outgoingUnicast <- &exchange{
		toFrom:  to,
		payload: payload,
	}
}

func (c *broadcastClientImpl) Broadcast(payload []byte) {
	c.outgoingBroadcast <- &exchange{
		payload: payload,
	}
}

func (c *broadcastClientImpl) Recv() (from types.IdentityKey, typ MessageType, payload []byte) {
	select {
	case in := <-c.incomingBroadcast:
		return in.toFrom, BROADCAST, in.payload
	case in := <-c.incomingUnicast:
		return in.toFrom, P2P, in.payload
	}
}

func (c *broadcastClientImpl) GetAuthKey() types.AuthKey {
	return c.id
}

func (c *broadcastClientImpl) processOutgoing() {
	for {
		select {
		case bOut := <-c.outgoingBroadcast:
			var mId messageId
			_, err := io.ReadFull(crand.Reader, mId[:])
			if err != nil {
				panic(err)
			}
			c.senders[mId], err = echo2.NewInitiator(mId[:], c.id, c.protocol, bOut.payload)
			if err != nil {
				panic(err)
			}
			r1output, err := c.senders[mId].Round1()
			if err != nil {
				panic(err)
			}
			// r2 is dummy for initiator
			_, _ = c.senders[mId].Round2(nil)

			for k, v := range r1output.Iter() {
				r1Buf := new(bytes.Buffer)
				enc := gob.NewEncoder(r1Buf)
				err = enc.Encode(v)
				if err != nil {
					panic(err)
				}
				msgBuf := new(bytes.Buffer)
				enc = gob.NewEncoder(msgBuf)
				err = enc.Encode(&message{
					Id:      mId,
					Type:    bcastType,
					Payload: r1Buf.Bytes(),
				})
				if err != nil {
					panic(err)
				}
				c.downstream.SendTo(k, msgBuf.Bytes())
			}
		case uOut := <-c.outgoingUnicast:
			msgBuf := new(bytes.Buffer)
			enc := gob.NewEncoder(msgBuf)
			err := enc.Encode(&message{
				Type:    p2pType,
				Payload: uOut.payload,
			})
			if err != nil {
				panic(err)
			}
			c.downstream.SendTo(uOut.toFrom, msgBuf.Bytes())
		}
	}
}

func (c *broadcastClientImpl) processIncoming() {
	for {
		from, payload := c.downstream.Recv()
		var msg message
		dec := gob.NewDecoder(bytes.NewReader(payload))
		if err := dec.Decode(&msg); err != nil {
			panic(err)
		}

		if msg.Type == p2pType {
			c.incomingUnicast <- &exchange{
				toFrom:  from,
				payload: msg.Payload,
			}
		}

		if msg.Type == bcastType {
			if _, ok := c.responders[msg.Id]; !ok {
				var err error
				c.responders[msg.Id], err = echo2.NewResponder(msg.Id[:], c.id, c.protocol, from)
				if err != nil {
					panic(err)
				}
				// round 1 is dummy for responders
				_, _ = c.responders[msg.Id].Round1()
			}

			var r2In echo2.Round1P2P
			dec := gob.NewDecoder(bytes.NewReader(msg.Payload))
			if err := dec.Decode(&r2In); err != nil {
				panic(err)
			}

			r2Out, err := c.responders[msg.Id].Round2(&r2In)
			if err != nil {
				panic(err)
			}
			for k, v := range r2Out.Iter() {
				r2Buf := new(bytes.Buffer)
				enc := gob.NewEncoder(r2Buf)
				err = enc.Encode(v)
				if err != nil {
					panic(err)
				}
				msgBuf := new(bytes.Buffer)
				enc = gob.NewEncoder(msgBuf)
				err := enc.Encode(&message{
					Id:      msg.Id,
					Type:    echoType,
					Payload: r2Buf.Bytes(),
				})
				if err != nil {
					panic(err)
				}

				c.downstream.SendTo(k, msgBuf.Bytes())
			}
		}
		if msg.Type == echoType {
			if _, ok := c.messageBuffer[msg.Id]; !ok {
				c.messageBuffer[msg.Id] = network.NewRoundMessages[types.Protocol, *echo2.Round2P2P]()
			}

			var r3In echo2.Round2P2P
			dec := gob.NewDecoder(bytes.NewReader(msg.Payload))
			if err := dec.Decode(&r3In); err != nil {
				panic(err)
			}
			c.messageBuffer[msg.Id].Put(from, &r3In)
		}

		if receiver, ok := c.responders[msg.Id]; ok {
			if r3In, ok := c.messageBuffer[msg.Id]; ok {
				// in 3rd round everyone receives n - 2 echos (every party minus initiator minus self, message from
				// initiator is in 2nd round
				if len(r3In.Keys()) == c.protocol.Participants().Size()-2 {
					received, err := receiver.Round3(c.messageBuffer[msg.Id])
					if err != nil {
						panic(err)
					}
					c.incomingBroadcast <- &exchange{
						toFrom:  c.responders[msg.Id].Initiator,
						payload: received,
					}
					delete(c.responders, msg.Id)
					delete(c.messageBuffer, msg.Id)
				}
			}
		}
	}
}
