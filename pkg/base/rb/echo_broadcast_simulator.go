package rb

import (
	crand "crypto/rand"
	"encoding/json"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"io"
	"slices"
	"sync"
)

var (
	P2P       messageType = "p2p"
	BROADCAST messageType = "broadcast"
	ECHO      messageType = "echo"
)

type correlationId [16]byte

type messageType string

type messageBroadcast struct {
	CorrelationId correlationId `json:"correlationId"`
	Payload       []byte        `json:"payload"`
}

type messageEcho struct {
	From          string        `json:"from"`
	CorrelationId correlationId `json:"correlationId"`
	Payload       []byte        `json:"payload"`
}

type message struct {
	Type    messageType `json:"type"`
	Payload []byte      `json:"payload"`
}

type broadcastBuffer struct {
	me         types.IdentityKey
	identities []types.IdentityKey
	lock       sync.Mutex
	cond       *sync.Cond
	froms      map[correlationId]types.IdentityKey
	payloads   map[correlationId]map[string][]byte
}

func newBroadcastBuffer(me types.IdentityKey, identities []types.IdentityKey) *broadcastBuffer {
	b := &broadcastBuffer{
		me:         me,
		identities: identities,
		lock:       sync.Mutex{},
		froms:      make(map[correlationId]types.IdentityKey),
		payloads:   make(map[correlationId]map[string][]byte),
	}
	b.cond = sync.NewCond(&b.lock)
	return b
}

func (b *broadcastBuffer) putBroadcast(corrId correlationId, from types.IdentityKey, payload []byte) {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()

	// TODO: check if already there
	b.froms[corrId] = from
	if _, ok := b.payloads[corrId]; !ok {
		b.payloads[corrId] = make(map[string][]byte)
	}
	b.payloads[corrId][from.String()] = payload
	b.cond.Broadcast()
}

func (b *broadcastBuffer) putEcho(corrId correlationId, from string, payload []byte) {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()

	if _, ok := b.payloads[corrId]; !ok {
		b.payloads[corrId] = make(map[string][]byte)
	}
	b.payloads[corrId][from] = payload
	b.cond.Broadcast()
}

func (b *broadcastBuffer) get() (types.IdentityKey, []byte) {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()

	var from types.IdentityKey
	var payload []byte
	for {
		from, payload = b.extract()
		if payload == nil {
			b.cond.Wait()
			continue
		} else {
			break
		}
	}

	return from, payload
}

func (b *broadcastBuffer) extract() (types.IdentityKey, []byte) {
	for corrId, from := range b.froms {
		payloads := b.payloads[corrId]
		allPayloads := [][]byte{}
		for _, id := range b.identities {
			if id.Equal(b.me) {
				continue
			}

			if p, ok := payloads[id.String()]; !ok {
				return nil, nil
			} else {
				allPayloads = append(allPayloads, p)
			}
		}

		// here we know, that we get echo from everyone, so let's delete them and check if equal
		delete(b.froms, corrId)
		delete(b.payloads, corrId)
		b.cond.Broadcast()

		for i := 0; i < len(allPayloads)-1; i++ {
			if !slices.Equal(allPayloads[i], allPayloads[i+1]) {
				panic("someone is cheating")
			}
		}

		return from, allPayloads[0]
	}

	return nil, nil
}

type unicastBuffer struct {
	lock     sync.Mutex
	cond     *sync.Cond
	froms    []types.IdentityKey
	payloads [][]byte
}

func newUnicastBuffer() *unicastBuffer {
	b := &unicastBuffer{
		lock:     sync.Mutex{},
		froms:    []types.IdentityKey{},
		payloads: [][]byte{},
	}
	b.cond = sync.NewCond(&b.lock)
	return b
}

func (b *unicastBuffer) put(from types.IdentityKey, payload []byte) {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()
	b.froms = append(b.froms, from)
	b.payloads = append(b.payloads, payload)
	b.cond.Broadcast()
}

func (b *unicastBuffer) get() (from types.IdentityKey, message []byte) {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()
	for len(b.froms) == 0 {
		b.cond.Wait()
	}

	from = b.froms[0]
	message = b.payloads[0]
	b.froms = b.froms[1:]
	b.payloads = b.payloads[1:]

	return from, message
}

type simulatorEchoBroadcast struct {
	auth    Auth
	uBuffer *unicastBuffer
	bBuffer *broadcastBuffer
}

func NewEchoBroadcast(auth Auth) EchoBroadcast {
	eb := &simulatorEchoBroadcast{
		auth:    auth,
		uBuffer: newUnicastBuffer(),
		bBuffer: newBroadcastBuffer(auth.GetCoordinator().GetAuthKey(), auth.GetCoordinator().GetParticipants()),
	}

	go eb.runStateMachine()
	return eb
}

func (e *simulatorEchoBroadcast) Send(to types.IdentityKey, payload []byte) error {
	ebm := &message{
		Type:    P2P,
		Payload: payload,
	}
	ebmSerialised, err := json.Marshal(ebm)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot serialise message")
	}

	return e.auth.Send(to, ebmSerialised)
}

func (e *simulatorEchoBroadcast) Receive() (from types.IdentityKey, message []byte, err error) {
	from, message = e.uBuffer.get()
	return from, message, nil
}

func (e *simulatorEchoBroadcast) Broadcast(payload []byte) error {
	var corrId correlationId
	_, err := io.ReadFull(crand.Reader, corrId[:])
	if err != nil {
		return errs.WrapFailed(err, "cannot sample correlation id")
	}
	b := &messageBroadcast{
		CorrelationId: corrId,
		Payload:       payload,
	}
	bSerialized, err := json.Marshal(b)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot serialise message")
	}
	ebm := &message{
		Type:    BROADCAST,
		Payload: bSerialized,
	}
	ebmSerialised, err := json.Marshal(ebm)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot serialise message")
	}
	for _, id := range e.auth.GetCoordinator().GetParticipants() {
		if id.Equal(e.auth.GetCoordinator().GetAuthKey()) {
			continue
		}
		err = e.auth.Send(id, ebmSerialised)
		if err != nil {
			return errs.WrapFailed(err, "cannot send message")
		}
	}

	return nil
}

func (e *simulatorEchoBroadcast) ReceiveBroadcast() (from types.IdentityKey, message []byte, err error) {
	from, message = e.bBuffer.get()
	return from, message, nil
}

func (e *simulatorEchoBroadcast) runStateMachine() {
	for {
		f, m, err := e.auth.Receive()
		if err != nil {
			panic(err) // TODO: handle
		}

		var ebm message
		err = json.Unmarshal(m, &ebm)
		if err != nil {
			panic(err) // TODO: handle
		}

		switch ebm.Type {
		case P2P:
			e.handleP2P(f, ebm.Payload)
			continue
		case BROADCAST:
			var bMessage messageBroadcast
			err = json.Unmarshal(ebm.Payload, &bMessage)
			if err != nil {
				panic(err) // TODO: handle
			}
			err = e.handleBroadcast(f, &bMessage)
			if err != nil {
				panic(err) // TODO: handle
			}
			continue
		case ECHO:
			var eMessage messageEcho
			err = json.Unmarshal(ebm.Payload, &eMessage)
			if err != nil {
				panic(err) // TODO: handle
			}
			e.handleEcho(f, &eMessage)
			continue
		}
	}
}

func (e *simulatorEchoBroadcast) handleP2P(from types.IdentityKey, payload []byte) {
	e.uBuffer.put(from, payload)
}

func (e *simulatorEchoBroadcast) handleBroadcast(from types.IdentityKey, payload *messageBroadcast) error {
	e.bBuffer.putBroadcast(payload.CorrelationId, from, payload.Payload)

	for _, id := range e.auth.GetCoordinator().GetParticipants() {
		if id.Equal(from) || id.Equal(e.auth.GetCoordinator().GetAuthKey()) {
			continue
		}

		echo := &messageEcho{
			From:          from.String(),
			CorrelationId: payload.CorrelationId,
			Payload:       payload.Payload,
		}
		echoSerialized, err := json.Marshal(echo)
		if err != nil {
			return err
		}
		ebm := &message{
			Type:    ECHO,
			Payload: echoSerialized,
		}
		ebmSerialized, err := json.Marshal(ebm)
		if err != nil {
			return err
		}

		err = e.auth.Send(id, ebmSerialized)
	}

	return nil
}

func (e *simulatorEchoBroadcast) handleEcho(from types.IdentityKey, m *messageEcho) {
	e.bBuffer.putEcho(m.CorrelationId, from.String(), m.Payload)
}
