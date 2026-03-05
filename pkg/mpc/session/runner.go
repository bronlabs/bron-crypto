package session

import (
	"io"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/errs-go/errs"
)

const (
	r1CorrelationID = "SessionSetupR1"
	r2CorrelationID = "SessionSetupR2"
	r3CorrelationID = "SessionSetupR3"
)

type runner struct {
	party *Participant
}

// NewSessionRunner creates a new session setup runner.
func NewSessionRunner(id sharing.ID, quorum ds.Set[sharing.ID], prng io.Reader) (network.Runner[*Context], error) {
	p, err := NewParticipant(id, quorum, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}
	r := &runner{
		party: p,
	}
	return r, nil
}

func (r *runner) Run(rt *network.Router) (*Context, error) {
	quorum := hashset.NewComparable(r.party.sortedQuorum...).Freeze()

	// round 1
	r1bo, err := r.party.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2bi, err := exchange.BroadcastExchange(rt, r1CorrelationID, quorum, r1bo)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}

	// round 2
	r2uo, err := r.party.Round2(r2bi)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3ui, err := exchange.UnicastExchange(rt, r2CorrelationID, r2uo)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange unicast")
	}

	// round 3
	r3uo, err := r.party.Round3(r3ui)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	r4ui, err := exchange.UnicastExchange(rt, r3CorrelationID, r3uo)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange unicast")
	}

	// round 4
	ctx, err := r.party.Round4(r4ui)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	return ctx, nil
}
