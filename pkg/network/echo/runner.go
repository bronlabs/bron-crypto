package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/errs-go/errs"
)

type echoBroadcastRunner[B any] struct {
	party         *Participant[B]
	correlationID string
	message       B
}

// NewEchoBroadcastRunner constructs an echo broadcast runner for the given party and quorum.
func NewEchoBroadcastRunner[B any](sharingID sharing.ID, quorum network.Quorum, correlationID string, message B) (network.Runner[network.RoundMessages[B]], error) {
	party, err := NewParticipant[B](sharingID, quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create participant")
	}

	r := &echoBroadcastRunner[B]{
		party,
		correlationID,
		message,
	}
	return r, nil
}

// Run executes the three-round echo broadcast protocol over the provided router.
func (r *echoBroadcastRunner[B]) Run(rt *network.Router) (network.RoundMessages[B], error) {
	// r1
	r1Out, err := r.party.Round1(r.message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to run round 1")
	}
	r2In, err := network.ExchangeUnicastSimple(rt, r.correlationID+":EchoRound1P2P", r1Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to exchange unicast")
	}

	// r2
	r2Out, err := r.party.Round2(r2In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to run round 2")
	}
	r3In, err := network.ExchangeUnicastSimple(rt, r.correlationID+":EchoRound2P2P", r2Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to exchange broadcast")
	}

	// r3
	output, err := r.party.Round3(r3In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to run round 3")
	}

	return output, nil
}
