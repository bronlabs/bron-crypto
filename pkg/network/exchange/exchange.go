package exchange

import (
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/echo"
	"github.com/bronlabs/errs-go/errs"
)

const (
	unicastPrefix   = "UNICAST:"
	broadcastPrefix = "BROADCAST:"
)

func UnicastSend[U any](rt *network.Router, correlationID string, unicastMessagesOut network.RoundMessages[U]) error {
	err := network.SendUnicast(rt, correlationID+unicastPrefix, unicastMessagesOut)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot send unicast")
	}
	return nil
}

func UnicastReceive[U any](rt *network.Router, correlationID string, quorum network.Quorum) (network.RoundMessages[U], error) {
	unicastMessagesIn, err := network.ReceiveUnicast[U](rt, correlationID+unicastPrefix, quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot receive unicast")
	}
	return unicastMessagesIn, nil
}

// UnicastExchange performs a unicast-only exchange where each party sends distinct messages.
func UnicastExchange[U any](rt *network.Router, correlationID string, unicastMessagesOut network.RoundMessages[U]) (unicastMessagesIn network.RoundMessages[U], err error) {
	err = network.SendUnicast(rt, correlationID+unicastPrefix, unicastMessagesOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot send unicast")
	}
	quorum := unicastMessagesOut.Keys()
	unicastMessagesIn, err = network.ReceiveUnicast[U](rt, correlationID+unicastPrefix, hashset.NewComparable(quorum...).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange unicast")
	}
	return unicastMessagesIn, nil
}

// BroadcastExchange performs an echo-broadcast round with the given message.
func BroadcastExchange[B any](rt *network.Router, correlationID string, quorum network.Quorum, broadcastMessageOut B) (broadcastMessagesIn network.RoundMessages[B], err error) {
	broadcastMessagesIn, err = echo.ExchangeEchoBroadcast(rt, correlationID+broadcastPrefix, quorum, broadcastMessageOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}
	return broadcastMessagesIn, nil
}

// Exchange performs a combined broadcast and unicast exchange under a shared correlation ID.
func Exchange[B any, U any](rt *network.Router, correlationID string, quorum network.Quorum, broadcastMessageOut B, unicastMessagesOut network.RoundMessages[U]) (broadcastMessagesIn network.RoundMessages[B], unicastMessagesIn network.RoundMessages[U], err error) {
	broadcastMessagesIn, err = BroadcastExchange(rt, correlationID, quorum, broadcastMessageOut)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}
	unicastMessagesIn, err = UnicastExchange(rt, correlationID, unicastMessagesOut)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot exchange unicast")
	}
	return broadcastMessagesIn, unicastMessagesIn, nil
}
