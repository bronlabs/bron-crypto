package gennaro

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

type gennaroDkgRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	party *Participant[G, S]
}

// NewGennaroDKGRunner constructs a network runner that drives the three DKG rounds.
func NewGennaroDKGRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, group algebra.PrimeGroup[G, S], accessStructure *threshold.Threshold, niCompilerName compiler.Name, prng io.Reader) (network.Runner[*DKGOutput[G, S]], error) {
	party, err := NewParticipant(ctx, group, accessStructure, niCompilerName, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}
	return &gennaroDkgRunner[G, S]{party}, nil
}

// Run executes the DKG rounds using the provided router and returns the final output.
func (r *gennaroDkgRunner[G, S]) Run(rt *network.Router) (*DKGOutput[G, S], error) {
	// r1
	r1OutB, err := r.party.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2InB, err := exchange.BroadcastExchange(rt, "GennaroDKGRound1", r.party.ac.Shareholders(), r1OutB)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}

	// r2
	r2OutB, r2OutU, err := r.party.Round2(r2InB)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3InB, r3InU, err := exchange.Exchange(rt, "GennaroDKGRound2", r.party.ac.Shareholders(), r2OutB, r2OutU)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}

	// r3
	dkgOutput, err := r.party.Round3(r3InB, r3InU)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}

	return dkgOutput, nil
}
