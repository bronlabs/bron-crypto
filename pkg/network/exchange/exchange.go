package exchange

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/echo"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

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

func ExchangeBroadcast[B any](rt *network.Router, correlationId string, broadcastMessageOut B) (broadcastMessagesIn network.RoundMessages[B], err error) {
	broadcastMessagesIn, err = echo.ExchangeEchoBroadcastSimple(rt, correlationId+":BROADCAST", broadcastMessageOut)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange unicast")
	}
	return broadcastMessagesIn, nil
}

func ExchangeUnicast[U any](rt *network.Router, correlationId string, unicastMessagesOut network.RoundMessages[U]) (unicastMessagesIn network.RoundMessages[U], err error) {
	unicastMessagesIn, err = network.ExchangeUnicastSimple(rt, correlationId+":UNICAST", unicastMessagesOut)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange unicast")
	}
	return unicastMessagesIn, nil
}

func SendUnicast[U any](rt *network.Router, correlationId string, unicastMessageOut network.RoundMessages[U]) error {
	return network.SendUnicast(rt, correlationId+":UNICAST", unicastMessageOut)
}

func ReceiveUnicast[U any](rt *network.Router, correlationId string, from ...sharing.ID) (unicastMessagesIn network.RoundMessages[U], err error) {
	return network.ReceiveUnicast[U](rt, correlationId+":UNICAST", from...)
}
