package stack

import (
	"bytes"
	"encoding/gob"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

type Stack interface {
	Dial(id types.AuthKey, protocol types.Protocol) ProtocolClient
}

type ProtocolClient interface {
	RoundSend(roundId string, broadcastMessage []byte, unicastMessages ds.Map[types.IdentityKey, []byte])
	RoundReceive(roundId string, broadcastFrom ds.Set[types.IdentityKey], unicastFrom ds.Set[types.IdentityKey]) (b ds.Map[types.IdentityKey, []byte], u ds.Map[types.IdentityKey, []byte])
}

func RoundSend[B network.Message[P], U network.Message[P], P types.Protocol](stack ProtocolClient, roundId string, broadcast B, unicast network.RoundMessages[P, U]) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(broadcast)
	if err != nil {
		panic(err)
	}
	b := buf.Bytes()

	u := hashmap.NewHashableHashMap[types.IdentityKey, []byte]()
	for id, msg := range unicast.Iter() {
		buf := new(bytes.Buffer)
		enc := gob.NewEncoder(buf)
		err := enc.Encode(msg)
		if err != nil {
			panic(err)
		}
		u.Put(id, buf.Bytes())
	}

	stack.RoundSend(roundId, b, u)
}

func RoundSendBroadcastOnly[B network.Message[P], P types.Protocol](stack ProtocolClient, roundId string, broadcast B) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(broadcast)
	if err != nil {
		panic(err)
	}
	b := buf.Bytes()

	stack.RoundSend(roundId, b, nil)
}

func RoundSendUnicastOnly[U network.Message[P], P types.Protocol](stack ProtocolClient, roundId string, unicast network.RoundMessages[P, U]) {
	var u ds.Map[types.IdentityKey, []byte]
	if unicast != nil {
		u = hashmap.NewHashableHashMap[types.IdentityKey, []byte]()
		for id, msg := range unicast.Iter() {
			buf := new(bytes.Buffer)
			enc := gob.NewEncoder(buf)
			err := enc.Encode(msg)
			if err != nil {
				panic(err)
			}
			u.Put(id, buf.Bytes())
		}
	}

	stack.RoundSend(roundId, nil, u)
}

func RoundReceive[B network.Message[P], U network.Message[P], P types.Protocol](stack ProtocolClient, roundId string, fromBroadcast, fromUnicast ds.Set[types.IdentityKey]) (b network.RoundMessages[P, B], u network.RoundMessages[P, U]) {
	bRaw, uRaw := stack.RoundReceive(roundId, fromBroadcast, fromUnicast)

	b = hashmap.NewHashableHashMap[types.IdentityKey, B]()
	for from, payload := range bRaw.Iter() {
		dec := gob.NewDecoder(bytes.NewReader(payload))
		var bMsg B
		err := dec.Decode(&bMsg)
		if err != nil {
			panic(err)
		}
		b.Put(from, bMsg)
	}

	u = hashmap.NewHashableHashMap[types.IdentityKey, U]()
	for from, payload := range uRaw.Iter() {
		dec := gob.NewDecoder(bytes.NewReader(payload))
		var uMsg U
		err := dec.Decode(&uMsg)
		if err != nil {
			panic(err)
		}
		u.Put(from, uMsg)
	}

	return b, u
}

func RoundReceiveBroadcastOnly[B network.Message[P], P types.Protocol](stack ProtocolClient, roundId string, fromBroadcast ds.Set[types.IdentityKey]) network.RoundMessages[P, B] {
	bRaw, _ := stack.RoundReceive(roundId, fromBroadcast, nil)

	b := hashmap.NewHashableHashMap[types.IdentityKey, B]()
	for from, payload := range bRaw.Iter() {
		dec := gob.NewDecoder(bytes.NewReader(payload))
		var bMsg B
		err := dec.Decode(&bMsg)
		if err != nil {
			panic(err)
		}
		b.Put(from, bMsg)
	}

	return b
}

func RoundReceiveUnicastOnly[U network.Message[P], P types.Protocol](stack ProtocolClient, roundId string, fromUnicast ds.Set[types.IdentityKey]) network.RoundMessages[P, U] {
	_, uRaw := stack.RoundReceive(roundId, nil, fromUnicast)

	u := hashmap.NewHashableHashMap[types.IdentityKey, U]()
	for from, payload := range uRaw.Iter() {
		dec := gob.NewDecoder(bytes.NewReader(payload))
		var uMsg U
		err := dec.Decode(&uMsg)
		if err != nil {
			panic(err)
		}
		u.Put(from, uMsg)
	}

	return u
}
