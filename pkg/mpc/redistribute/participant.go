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
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Participant executes the two-round share redistribution protocol.
type Participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ctx                  *session.Context
	recoverers           ds.Set[sharing.ID]
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
// The caller supplies the current session context, the qualified recoverer set
// from the previous access structure, the caller's previous shard when the
// caller is a recoverer, and the next access structure to redistribute into.
// The session quorum must equal the union of the recoverers and the
// shareholders of the next access structure.
func NewParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, recoverers ds.Set[sharing.ID], prevShard *mpc.BaseShard[G, S], nextAccessStructure accessstructures.Monotone, prng io.Reader) (*Participant[G, S], error) {
	if ctx == nil || recoverers == nil || nextAccessStructure == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments (nil)")
	}
	if recoverers.Contains(ctx.HolderID()) {
		if prevShard == nil {
			return nil, ErrInvalidArgument.WithMessage("invalid arguments (nil)")
		}
		if !prevShard.MSP().Accepts(recoverers.List()...) {
			return nil, ErrInvalidArgument.WithMessage("unqualified recoverers set")
		}
	}
	for recovererID := range recoverers.Iter() {
		if !ctx.Quorum().Contains(recovererID) {
			return nil, ErrInvalidArgument.WithMessage("invalid arguments (recoverer not in quorum)")
		}
	}
	for recovereeID := range nextAccessStructure.Shareholders().Iter() {
		if !ctx.Quorum().Contains(recovereeID) {
			return nil, ErrInvalidArgument.WithMessage("invalid arguments (recoveree not in quorum)")
		}
	}
	allParties := recoverers.Union(nextAccessStructure.Shareholders())
	if !allParties.Equal(ctx.Quorum()) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments (quorum does not match recoverers and next access structure)")
	}

	p := &Participant[G, S]{
		ctx:                  ctx,
		recoverers:           recoverers,
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

func (p *Participant[G, S]) isRecoverer(id sharing.ID) bool {
	return p.recoverers.Contains(id)
}

func (p *Participant[G, S]) otherRecoverers() iter.Seq[sharing.ID] {
	return func(yield func(sharing.ID) bool) {
		for id := range p.ctx.OtherPartiesOrdered() {
			if !p.isRecoverer(id) {
				continue
			}
			if ok := yield(id); !ok {
				return
			}
		}
	}
}

func (p *Participant[G, S]) isRecoveree(id sharing.ID) bool {
	return p.nextAccessStructures.Shareholders().Contains(id)
}
