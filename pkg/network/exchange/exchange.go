package exchange

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/echo"
)

// Exchange performs a combined broadcast and unicast exchange under a shared correlation ID.
func Exchange[B any, U any](rt *network.Router, correlationId string, broadcastMessageOut B, unicastMessagesOut network.RoundMessages[U]) (broadcastMessagesIn network.RoundMessages[B], unicastMessagesIn network.RoundMessages[U], err error) {
	broadcastMessagesIn, err = echo.ExchangeEchoBroadcastSimple(rt, correlationId+":BROADCAST", broadcastMessageOut)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot exchange broadcast")
	}
	unicastMessagesIn, err = network.ExchangeUnicastSimple(rt, correlationId+":UNICAST", unicastMessagesOut)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot exchange unicast")
	}
	return broadcastMessagesIn, unicastMessagesIn, nil
}

// ExchangeBroadcast performs an echo-broadcast round with the given message.
func ExchangeBroadcast[B any](rt *network.Router, correlationId string, broadcastMessageOut B) (broadcastMessagesIn network.RoundMessages[B], err error) {
	broadcastMessagesIn, err = echo.ExchangeEchoBroadcastSimple(rt, correlationId+":BROADCAST", broadcastMessageOut)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange unicast")
	}
	return broadcastMessagesIn, nil
}

// ExchangeUnicast performs a unicast-only exchange where each party sends distinct messages.
func ExchangeUnicast[U any](rt *network.Router, correlationId string, unicastMessagesOut network.RoundMessages[U]) (unicastMessagesIn network.RoundMessages[U], err error) {
	unicastMessagesIn, err = network.ExchangeUnicastSimple(rt, correlationId+":UNICAST", unicastMessagesOut)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange unicast")
	}
	return unicastMessagesIn, nil
}
