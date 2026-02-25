package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
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
	err = network.SendUnicast(rt, r.correlationID+":EchoRound1P2P", r1Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to send unicast")
	}
	r2In, err := network.ReceiveUnicast[*Round1P2P](rt, r.correlationID+":EchoRound1P2P", r.party.Quorum())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to receive unicast")
	}

	// r2
	r2Out, err := r.party.Round2(r2In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to run round 2")
	}
	err = network.SendUnicast(rt, r.correlationID+":EchoRound2P2P", r2Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to send unicast")
	}
	r3In, err := network.ReceiveUnicast[*Round2P2P](rt, r.correlationID+":EchoRound2P2P", r.party.Quorum())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to receive unicast")
	}

	// r3
	output, err := r.party.Round3(r3In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to run round 3")
	}

	return output, nil
}
