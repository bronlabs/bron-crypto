package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type echoBroadcastRunner[B any] struct {
	party         *Participant[B]
	correlationId string
	message       B
}

func NewEchoBroadcastRunner[B any](sharingId sharing.ID, quorum network.Quorum, correlationId string, message B) (network.Runner[network.RoundMessages[B]], error) {
	party, err := NewParticipant[B](sharingId, quorum)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create participant")
	}

	r := &echoBroadcastRunner[B]{
		party,
		correlationId,
		message,
	}
	return r, nil
}

func (r *echoBroadcastRunner[B]) Run(rt *network.Router) (network.RoundMessages[B], error) {
	// r1
	r1Out, err := r.party.Round1(r.message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to run round 1")
	}
	r2In, err := network.ExchangeUnicastSimple(rt, r.correlationId+":EchoRound1P2P", r1Out)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to exchange unicast")
	}

	// r2
	r2Out, err := r.party.Round2(r2In)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to run round 2")
	}
	r3In, err := network.ExchangeUnicastSimple(rt, r.correlationId+":EchoRound2P2P", r2Out)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to exchange broadcast")
	}

	// r3
	output, err := r.party.Round3(r3In)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to run round 3")
	}

	return output, nil
}
