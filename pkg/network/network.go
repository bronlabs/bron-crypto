package network

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type MessageLike interface {
	Validate(parameters ...int) error
}

type RoundMessages[MessageT MessageLike] ds.Map[types.IdentityKey, MessageT]

func NewRoundMessages[MessageT MessageLike]() RoundMessages[MessageT] {
	return hashmap.NewHashableHashMap[types.IdentityKey, MessageT]()
}

func ValidateMessage(roundMessage MessageLike, parameters ...int) error {
	if roundMessage == nil {
		return errs.NewIsNil("round message")
	}
	if err := roundMessage.Validate(parameters...); err != nil {
		return errs.WrapValidation(err, "invalid round message")
	}
	return nil
}

func ValidateMessages[MessageT MessageLike](senders ds.Set[types.IdentityKey], receiver types.IdentityKey, roundMessages RoundMessages[MessageT], parameters ...int) error {
	if roundMessages == nil {
		return errs.NewIsNil("round messages")
	}
	for sender := range senders.Iter() {
		if sender.Equal(receiver) {
			continue
		}
		message, exists := roundMessages.Get(sender)
		if !exists {
			return errs.NewMissing("receiver %s got no message from sender %s",
				bitstring.TruncateWithEllipsis(receiver.String(), 16),
				bitstring.TruncateWithEllipsis(sender.String(), 16))
		}
		if err := ValidateMessage(message, parameters...); err != nil {
			return errs.WrapValidation(err, "receiver %s got invalid message from sender %s",
				bitstring.TruncateWithEllipsis(receiver.String(), 16),
				bitstring.TruncateWithEllipsis(sender.String(), 16))
		}
	}
	return nil
}
