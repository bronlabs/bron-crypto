package network

import (
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	t "github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Message[ProtocolT t.Protocol] interface {
	Validate(protocol ProtocolT) error
}

type RoundMessages[ProtocolT t.Protocol, MessageT Message[ProtocolT]] ds.Map[t.IdentityKey, MessageT]

func NewRoundMessages[ProtocolT t.Protocol, MessageT Message[ProtocolT]]() RoundMessages[ProtocolT, MessageT] {
	return hashmap.NewHashableHashMap[t.IdentityKey, MessageT]()
}

func ValidateMessages[ProtocolT t.Protocol, MessageT Message[ProtocolT]](protocol ProtocolT, senders ds.Set[t.IdentityKey], receiver t.IdentityKey, messages RoundMessages[ProtocolT, MessageT]) error {
	var receiverString string
	for sender := range senders.Iter() {
		if receiver != nil && sender.Equal(receiver) {
			continue
		}
		message, exists := messages.Get(sender)
		if !exists {
			if receiver != nil {
				receiverString = bitstring.TruncateWithEllipsis(receiver.String(), 16)
			}
			return errs.NewMissing("receiver %s got no message from sender %s",
				receiverString, bitstring.TruncateWithEllipsis(sender.String(), 16))
		}
		if err := message.Validate(protocol); err != nil {
			if receiver != nil {
				receiverString = bitstring.TruncateWithEllipsis(receiver.String(), 16)
			}
			return errs.WrapValidation(err, "receiver %s got invalid message from sender %s",
				receiverString, bitstring.TruncateWithEllipsis(sender.String(), 16))
		}
	}
	return nil
}

func SortMessages[ProtocolT t.Protocol, MessageT Message[ProtocolT]](protocol ProtocolT, messages RoundMessages[ProtocolT, MessageT]) ([]MessageT, error) {
	identitySpace := t.NewIdentitySpace(protocol.Participants())
	sortedIdentityIndices := identitySpace.Keys()
	sort.Slice(sortedIdentityIndices, func(i, j int) bool { return sortedIdentityIndices[i] < sortedIdentityIndices[j] })
	sortedMessages := make([]MessageT, 0, messages.Size())
	for _, identityIndex := range sortedIdentityIndices {
		identityKey, exists := identitySpace.Get(identityIndex)
		if !exists {
			return nil, errs.NewMissing("identity index %d not found", identityIndex)
		}
		message, exists := messages.Get(identityKey)
		if exists {
			sortedMessages = append(sortedMessages, message)
		}
	}
	return sortedMessages, nil
}
