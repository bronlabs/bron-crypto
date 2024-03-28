package network

import (
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

func ValidateMessages[ProtocolT t.Protocol, MessageT Message[ProtocolT]](receiver t.Participant[ProtocolT], senders ds.Set[t.IdentityKey], messages RoundMessages[ProtocolT, MessageT]) error {
	for sender := range senders.Iter() {
		if sender.Equal(receiver.IdentityKey()) {
			continue
		}
		message, exists := messages.Get(sender)
		if !exists {
			return errs.NewMissing("receiver %s got no message from sender %s",
				bitstring.TruncateWithEllipsis(receiver.IdentityKey().String(), 16),
				bitstring.TruncateWithEllipsis(sender.String(), 16))
		}
		if err := message.Validate(receiver.Protocol()); err != nil {
			return errs.WrapValidation(err, "receiver %s got invalid message from sender %s",
				bitstring.TruncateWithEllipsis(receiver.IdentityKey().String(), 16),
				bitstring.TruncateWithEllipsis(sender.String(), 16))
		}
	}
	return nil
}
