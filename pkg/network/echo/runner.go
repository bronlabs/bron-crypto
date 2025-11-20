package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

func RunEchoBroadcast[B any](rt *network.Router, sharingId sharing.ID, quorum network.Quorum, correlationId string, message B) (network.RoundMessages[B], error) {
	party, err := NewParticipant[B](sharingId, quorum)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create participant")
	}

	// r1
	r1Out, err := party.Round1(message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to run round 1")
	}
	r2In, err := network.ExchangeUnicastSimple(rt, correlationId+":EchoRound1P2P", toNative(r1Out))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to exchange unicast")
	}

	// r2
	r2Out, err := party.Round2(hashmap.NewImmutableComparableFromNativeLike(r2In))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to run round 2")
	}
	r3In, err := network.ExchangeUnicastSimple(rt, correlationId+":EchoRound2P2P", toNative(r2Out))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to exchange broadcast")
	}

	// r3
	output, err := party.Round3(hashmap.NewImmutableComparableFromNativeLike(r3In))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to run round 3")
	}

	return output, nil
}

func toNative[M any](messages network.OutgoingUnicasts[M]) map[sharing.ID]M {
	messagesMap, ok := messages.(*hashmap.ImmutableComparableHashMap[sharing.ID, M])
	if !ok {
		panic("this should never happen: unexpected type of messages")
	}
	nativeMap := make(map[sharing.ID]M)
	for id, msg := range messagesMap.Iter() {
		nativeMap[id] = msg
	}
	return nativeMap
}
