package redistribute

import (
	"io"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Participant executes the two-round share redistribution protocol.
type Participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ctx                  *session.Context
	prevShareholders     ds.Set[sharing.ID]
	prevShard            *mpc.BaseShard[G, S]
	nextAccessStructures accessstructures.Monotone
	prng                 io.Reader

	state state[G, S]
}

type state[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	round                      network.Round
	share                      *kw.Share[S]
	shareVerificationVector    *feldman.VerificationVector[G, S]
	subShareVerificationVector *feldman.VerificationVector[G, S]
}

// NewParticipant constructs a redistribution participant.
//
// The caller supplies the current session context, the qualified previous shareholders set
// from the previous access structure, the caller's previous shard
// and the next access structure to redistribute into.
// The session quorum must equal the union of the previous and the
// next shareholders of the next access structure.
func NewParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, prevShareholders ds.Set[sharing.ID], prevShard *mpc.BaseShard[G, S], nextAccessStructure accessstructures.Monotone, prng io.Reader) (*Participant[G, S], error) {
	if ctx == nil || prevShareholders == nil || nextAccessStructure == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments (nil)")
	}
	if prevShareholders.Contains(ctx.HolderID()) {
		if prevShard == nil {
			return nil, ErrInvalidArgument.WithMessage("invalid arguments (nil)")
		}
		if !prevShard.MSP().Accepts(prevShareholders.List()...) {
			return nil, ErrInvalidArgument.WithMessage("unqualified set")
		}
	}
	for prevShareholderID := range prevShareholders.Iter() {
		if !ctx.Quorum().Contains(prevShareholderID) {
			return nil, ErrInvalidArgument.WithMessage("invalid arguments (shareholder not in quorum)")
		}
	}
	for nextShareholderID := range nextAccessStructure.Shareholders().Iter() {
		if !ctx.Quorum().Contains(nextShareholderID) {
			return nil, ErrInvalidArgument.WithMessage("invalid arguments (shareholder not in quorum)")
		}
	}
	allParties := prevShareholders.Union(nextAccessStructure.Shareholders())
	if !allParties.Equal(ctx.Quorum()) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments (quorum does not match shareholders and next access structure)")
	}

	p := &Participant[G, S]{
		ctx:                  ctx,
		prevShareholders:     prevShareholders,
		prevShard:            prevShard,
		nextAccessStructures: nextAccessStructure,
		prng:                 prng,
		//nolint:exhaustruct // state is lazily initialised
		state: state[G, S]{
			round: 1,
		},
	}
	return p, nil
}

// SharingID returns the participant's holder identifier in the redistribution
// session.
func (p *Participant[G, S]) SharingID() sharing.ID {
	return p.ctx.HolderID()
}

func (p *Participant[G, S]) isPrevShareholder(id sharing.ID) bool {
	return p.prevShareholders.Contains(id)
}

func (p *Participant[G, S]) otherPrevShareholders() iter.Seq[sharing.ID] {
	return func(yield func(sharing.ID) bool) {
		for id := range p.ctx.OtherPartiesOrdered() {
			if !p.isPrevShareholder(id) {
				continue
			}
			if ok := yield(id); !ok {
				return
			}
		}
	}
}

func (p *Participant[G, S]) isNextShareholder(id sharing.ID) bool {
	return p.nextAccessStructures.Shareholders().Contains(id)
}
