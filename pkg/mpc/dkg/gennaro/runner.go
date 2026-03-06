package gennaro

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/errs-go/errs"
)

type runner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	party *Participant[G, S]
}

// NewRunner constructs a network runner that drives the three DKG rounds.
func NewRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, group algebra.PrimeGroup[G, S], accessStructure *accessstructures.Threshold, niCompilerName compiler.Name, prng io.Reader) (network.Runner[*DKGOutput[G, S]], error) {
	party, err := NewParticipant(ctx, group, accessStructure, niCompilerName, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}
	return &runner[G, S]{party}, nil
}

// Run executes the DKG rounds using the provided router and returns the final output.
func (r *runner[G, S]) Run(rt *network.Router) (*DKGOutput[G, S], error) {
	// r1
	r1OutB, r1OutU, err := r.party.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2InB, r2InU, err := exchange.Exchange(rt, "GennaroDKGRound1", r.party.ac.Shareholders(), r1OutB, r1OutU)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}

	// r2
	r2OutB, err := r.party.Round2(r2InB, r2InU)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3InB, err := exchange.BroadcastExchange(rt, "GennaroDKGRound2", r.party.ac.Shareholders(), r2OutB)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}

	// r3
	dkgOutput, err := r.party.Round3(r3InB)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}

	return dkgOutput, nil
}
