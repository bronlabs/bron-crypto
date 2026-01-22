package exchange

import (
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/echo"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// Exchange performs a combined broadcast and unicast exchange under a shared correlation ID.
func Exchange[B any, U any](rt *network.Router, correlationID string, broadcastMessageOut B, unicastMessagesOut network.RoundMessages[U]) (broadcastMessagesIn network.RoundMessages[B], unicastMessagesIn network.RoundMessages[U], err error) {
	broadcastMessagesIn, err = echo.ExchangeEchoBroadcastSimple(rt, correlationID+":BROADCAST", broadcastMessageOut)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}
	unicastMessagesIn, err = network.ExchangeUnicastSimple(rt, correlationID+":UNICAST", unicastMessagesOut)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot exchange unicast")
	}
	return broadcastMessagesIn, unicastMessagesIn, nil
}

// Broadcast performs an echo-broadcast round with the given message.
func Broadcast[B any](rt *network.Router, correlationID string, broadcastMessageOut B) (broadcastMessagesIn network.RoundMessages[B], err error) {
	broadcastMessagesIn, err = echo.ExchangeEchoBroadcastSimple(rt, correlationID+":BROADCAST", broadcastMessageOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}
	return broadcastMessagesIn, nil
}

// Unicast performs a unicast-only exchange where each party sends distinct messages.
func Unicast[U any](rt *network.Router, correlationID string, unicastMessagesOut network.RoundMessages[U]) (unicastMessagesIn network.RoundMessages[U], err error) {
	unicastMessagesIn, err = network.ExchangeUnicastSimple(rt, correlationID+":UNICAST", unicastMessagesOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange unicast")
	}
	return unicastMessagesIn, nil
}
