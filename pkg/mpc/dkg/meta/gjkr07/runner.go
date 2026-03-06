package gjkr07

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/errs-go/errs"
)

const (
	r1CorrelationID = "GJKR07DKGRound1"
	r2CorrelationID = "GJKR07DKGRound2"
)

type runner[
	S sharing.LinearShare[S, SV], SV algebra.PrimeFieldElement[SV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.RingElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.DealerFunc[S, SV, AC],
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	LFTW interface {
		sharing.Secret[LFTW]
		base.Transparent[LFTWV]
	}, LFTWV algebra.ModuleElement[LFTWV, WV],
] struct {
	party *Participant[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]
}

// NewRunner constructs a network runner that drives the three DKG rounds.
func NewRunner[
	S sharing.LinearShare[S, SV], SV algebra.PrimeFieldElement[SV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.RingElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.DealerFunc[S, SV, AC],
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	LFTW interface {
		sharing.Secret[LFTW]
		base.Transparent[LFTWV]
	}, LFTWV algebra.ModuleElement[LFTWV, WV],
](
	ctx *session.Context, group algebra.PrimeGroup[LFTSV, SV], lsss sharing.LiftableLSSS[S, SV, W, WV, DO, AC, DF, LFTS, LFTSV, LFTDF, LFTW, LFTWV], niCompilerName compiler.Name, prng io.Reader,
) (network.Runner[*DKGOutput[LFTDF, LFTS, LFTSV, S, SV, AC]], error) {
	party, err := NewParticipant(ctx, group, lsss, niCompilerName, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}
	return &runner[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]{party}, nil
}

// Run executes the DKG rounds using the provided router and returns the final output.
func (r *runner[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) Run(rt *network.Router) (*DKGOutput[LFTDF, LFTS, LFTSV, S, SV, AC], error) {
	// r1
	r1OutB, err := r.party.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2InB, err := exchange.BroadcastExchange(rt, r1CorrelationID, r.party.ac.Shareholders(), r1OutB)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}

	// r2
	r2OutB, r2OutU, err := r.party.Round2(r2InB)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3InB, r3InU, err := exchange.Exchange(rt, r2CorrelationID, r.party.ac.Shareholders(), r2OutB, r2OutU)
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
