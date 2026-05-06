package exchange

import (
	"context"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/echo"
)

const (
	unicastPrefix   = "UNICAST:"
	broadcastPrefix = "BROADCAST:"
)

func UnicastSend[U network.Message[P], P any](ctx context.Context, rt *network.Router, correlationID string, unicastMessagesOut network.RoundMessages[U, P]) error {
	err := network.SendUnicast(ctx, rt, correlationID+unicastPrefix, unicastMessagesOut)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot send unicast")
	}
	return nil
}

func UnicastReceive[U network.Message[P], P any](ctx context.Context, rt *network.Router, correlationID string, quorum network.Quorum) (network.RoundMessages[U, P], error) {
	unicastMessagesIn, err := network.ReceiveUnicast[U, P](ctx, rt, correlationID+unicastPrefix, quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot receive unicast")
	}
	return unicastMessagesIn, nil
}

// UnicastExchange performs a unicast-only exchange where each party sends distinct messages.
func UnicastExchange[U network.Message[P], P any](ctx context.Context, rt *network.Router, correlationID string, unicastMessagesOut network.RoundMessages[U, P]) (unicastMessagesIn network.RoundMessages[U, P], err error) {
	err = network.SendUnicast(ctx, rt, correlationID+unicastPrefix, unicastMessagesOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot send unicast")
	}
	quorum := unicastMessagesOut.Keys()
	unicastMessagesIn, err = network.ReceiveUnicast[U, P](ctx, rt, correlationID+unicastPrefix, hashset.NewComparable(quorum...).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange unicast")
	}
	return unicastMessagesIn, nil
}

// BroadcastExchange performs an echo-broadcast round with the given message.
func BroadcastExchange[B network.Message[P], P any](ctx context.Context, rt *network.Router, correlationID string, quorum network.Quorum, broadcastMessageOut B) (broadcastMessagesIn network.RoundMessages[B, P], err error) {
	broadcastMessagesIn, err = echo.ExchangeEchoBroadcast[B, P](ctx, rt, correlationID+broadcastPrefix, quorum, broadcastMessageOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}
	return broadcastMessagesIn, nil
}

// Exchange performs a combined broadcast and unicast exchange under a shared correlation ID.
func Exchange[B network.Message[P], U network.Message[P], P any](ctx context.Context, rt *network.Router, correlationID string, quorum network.Quorum, broadcastMessageOut B, unicastMessagesOut network.RoundMessages[U, P]) (broadcastMessagesIn network.RoundMessages[B, P], unicastMessagesIn network.RoundMessages[U, P], err error) {
	broadcastMessagesIn, err = BroadcastExchange(ctx, rt, correlationID, quorum, broadcastMessageOut)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}
	unicastMessagesIn, err = UnicastExchange(ctx, rt, correlationID, unicastMessagesOut)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot exchange unicast")
	}
	return broadcastMessagesIn, unicastMessagesIn, nil
}
