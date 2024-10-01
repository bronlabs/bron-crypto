package round

import (
	"bytes"
	"encoding/gob"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/broadcast"
	"sync"
)

var (
	_ Client = (*roundClientImpl)(nil)
)

type message struct {
	RoundId string
	Payload []byte
}

type roundClientImpl struct {
	downstream broadcast.Client

	unicastBuffer   map[string]ds.Map[types.IdentityKey, []byte]
	broadcastBuffer map[string]ds.Map[types.IdentityKey, []byte]

	bufferLock    sync.Mutex
	bufferCondVar *sync.Cond
}

func (c *roundClientImpl) Send(roundId string, b []byte, u ds.Map[types.IdentityKey, []byte]) {
	if b != nil {
		msg := &message{
			RoundId: roundId,
			Payload: b,
		}
		buf := new(bytes.Buffer)
		enc := gob.NewEncoder(buf)
		err := enc.Encode(msg)
		if err != nil {
			panic(err)
		}
		c.downstream.Broadcast(buf.Bytes())
	}

	if u != nil {
		for to, payload := range u.Iter() {
			msg := &message{
				RoundId: roundId,
				Payload: payload,
			}
			buf := new(bytes.Buffer)
			enc := gob.NewEncoder(buf)
			err := enc.Encode(msg)
			if err != nil {
				panic(err)
			}
			c.downstream.SendTo(to, buf.Bytes())
		}
	}
}

func (c *roundClientImpl) Receive(roundId string, fromB []types.IdentityKey, fromU []types.IdentityKey) (b ds.Map[types.IdentityKey, []byte], u ds.Map[types.IdentityKey, []byte]) {
	c.bufferCondVar.L.Lock()
	defer c.bufferCondVar.L.Unlock()
	for !c.hasAllMessage(roundId, fromB, fromU) {
		c.bufferCondVar.Wait()
	}
	if len(fromB) > 0 {
		b = c.broadcastBuffer[roundId]
	}
	if len(fromU) > 0 {
		u = c.unicastBuffer[roundId]
	}

	return b, u
}

func (c *roundClientImpl) GetAuthKey() types.AuthKey {
	return c.downstream.GetAuthKey()
}

func (c *roundClientImpl) processIncoming() {
	for {
		from, typ, payload := c.downstream.Recv()
		dec := gob.NewDecoder(bytes.NewBuffer(payload))
		var msg message
		err := dec.Decode(&msg)
		if err != nil {
			panic(err)
		}

		switch typ {
		case broadcast.P2P:
			c.processIncomingUnicast(from, &msg)
		case broadcast.BROADCAST:
			c.processIncomingBroadcast(from, &msg)
		}
	}
}

func (c *roundClientImpl) processIncomingUnicast(from types.IdentityKey, msg *message) {
	c.bufferCondVar.L.Lock()
	defer c.bufferCondVar.L.Unlock()
	if _, ok := c.unicastBuffer[msg.RoundId]; !ok {
		c.unicastBuffer[msg.RoundId] = hashmap.NewHashableHashMap[types.IdentityKey, []byte]()
	}
	c.unicastBuffer[msg.RoundId].Put(from, msg.Payload)
	c.bufferCondVar.Broadcast()
}

func (c *roundClientImpl) processIncomingBroadcast(from types.IdentityKey, msg *message) {
	c.bufferCondVar.L.Lock()
	defer c.bufferCondVar.L.Unlock()
	if _, ok := c.broadcastBuffer[msg.RoundId]; !ok {
		c.broadcastBuffer[msg.RoundId] = hashmap.NewHashableHashMap[types.IdentityKey, []byte]()
	}
	c.broadcastBuffer[msg.RoundId].Put(from, msg.Payload)
	c.bufferCondVar.Broadcast()
}

func (c *roundClientImpl) hasAllMessage(roundId string, fromB, fromU []types.IdentityKey) bool {
	if len(fromB) > 0 {
		buffer, ok := c.broadcastBuffer[roundId]
		if !ok {
			return false
		}
		for _, bId := range fromB {
			if !buffer.ContainsKey(bId) {
				return false
			}
		}
	}
	if len(fromU) > 0 {
		buffer, ok := c.unicastBuffer[roundId]
		if !ok {
			return false
		}
		for _, uId := range fromU {
			if !buffer.ContainsKey(uId) {
				return false
			}
		}
	}

	return true
}
