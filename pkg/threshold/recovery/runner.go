package recovery

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
	"github.com/bronlabs/errs-go/errs"
)

const (
	r1CorrelationID = "RecoveryRound1"
	r2CorrelationID = "RecoveryRound2"
)

type recovererRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	party *Recoverer[G, S]
}

type mislayerRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	party *Mislayer[G, S]
}

func NewRecovererRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](mislayerID sharing.ID, quorum network.Quorum, baseShard *tsig.BaseShard[G, S], prng io.Reader) (network.Runner[any], error) {
	party, err := NewRecoverer(mislayerID, quorum, baseShard, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create recoverer")
	}
	r := &recovererRunner[G, S]{
		party: party,
	}
	return r, nil
}

// NewMislayerRunner constructs a network runner that drives the three DKG rounds.
func NewMislayerRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](id sharing.ID, quorum network.Quorum, as *sharing.ThresholdAccessStructure, group algebra.PrimeGroup[G, S]) (network.Runner[*Output[G, S]], error) {
	party, err := NewMislayer(id, quorum, as, group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create mislayer")
	}
	r := &mislayerRunner[G, S]{
		party: party,
	}
	return r, nil
}

func (r *recovererRunner[G, S]) Run(rt *network.Router) (any, error) {
	recoverers := r.party.quorum.Clone().Unfreeze()
	recoverers.Remove(r.party.mislayerID)

	r1bOut, r1uOut, err := r.party.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r1bIn, r2uIn, err := exchange.Exchange(rt, r1CorrelationID, recoverers.Freeze(), r1bOut, r1uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange r1 messages")
	}

	r2Out, err := r.party.Round2(r1bIn, r2uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	err = exchange.UnicastSend(rt, r2CorrelationID, r2Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot send round 2")
	}

	//nolint:nilnil // no void type in go
	return nil, nil
}

// Run executes the DKG rounds using the provided router and returns the final output.
func (r *mislayerRunner[G, S]) Run(rt *network.Router) (*Output[G, S], error) {
	r2, err := exchange.UnicastReceive[*Round2P2P[G, S]](rt, r2CorrelationID, r.party.quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot receive round 2")
	}
	output, err := r.party.Round3(r2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}

	return output, nil
}
