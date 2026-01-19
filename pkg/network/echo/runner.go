package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type echoBroadcastRunner[B any] struct {
	party         *Participant[B]
	correlationId string
	message       B
}

// NewEchoBroadcastRunner constructs an echo broadcast runner for the given party and quorum.
func NewEchoBroadcastRunner[B any](sharingID sharing.ID, quorum network.Quorum, correlationId string, message B) (network.Runner[network.RoundMessages[B]], error) {
	party, err := NewParticipant[B](sharingID, quorum)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create participant")
	}

	r := &echoBroadcastRunner[B]{
		party,
		correlationId,
		message,
	}
	return r, nil
}

// Run executes the three-round echo broadcast protocol over the provided router.
func (r *echoBroadcastRunner[B]) Run(rt *network.Router) (network.RoundMessages[B], error) {
	// r1
	r1Out, err := r.party.Round1(r.message)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to run round 1")
	}
	r2In, err := network.ExchangeUnicastSimple(rt, r.correlationId+":EchoRound1P2P", r1Out)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to exchange unicast")
	}

	// r2
	r2Out, err := r.party.Round2(r2In)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to run round 2")
	}
	r3In, err := network.ExchangeUnicastSimple(rt, r.correlationId+":EchoRound2P2P", r2Out)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to exchange broadcast")
	}

	// r3
	output, err := r.party.Round3(r3In)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to run round 3")
	}

	return output, nil
}
