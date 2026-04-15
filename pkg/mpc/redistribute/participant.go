package redistribute

import (
	"io"
	"iter"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Participant executes the three-round share redistribution protocol.
type Participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ctx                  *session.Context
	zeroParticipant      *hjky.Participant[G, S]
	trustedDealerID      sharing.ID
	prevShareholders     ds.Set[sharing.ID]
	prevUnanimity        *unanimity.Unanimity
	prevShard            *mpc.BaseShard[G, S]
	nextAccessStructures accessstructures.Monotone
	prng                 io.Reader

	state state[G, S]
}

type state[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	round                   network.Round
	share                   *kw.Share[S]
	shareVerificationVector *feldman.VerificationVector[G, S]
	zeroVerificationVector  *feldman.VerificationVector[G, S]
}

// NewParticipant constructs a redistribution participant.
//
// The caller supplies the current session context, a trusted dealer identifier,
// the qualified previous-shareholder set from the previous access structure,
// the caller's previous shard, and the next access structure to redistribute
// into. The trusted dealer must be one of the previous shareholders; whenever
// inconsistencies in the old metadata are detected, they are checked against
// that party to support identifiable aborts.
//
// The session quorum must equal the union of the previous shareholders and the
// next access structure's shareholders.
func NewParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, trustedDealerID sharing.ID, prevShareholders ds.Set[sharing.ID], prevShard *mpc.BaseShard[G, S], nextAccessStructure accessstructures.Monotone, prng io.Reader) (*Participant[G, S], error) {
	if ctx == nil || prevShareholders == nil || nextAccessStructure == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments (nil)")
	}
	if !prevShareholders.Contains(trustedDealerID) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments (trusted dealer not in shareholders)")
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
	prevUnanimity, err := unanimity.NewUnanimityAccessStructure(prevShareholders)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create unanimity access structure")
	}

	p := &Participant[G, S]{
		ctx:                  ctx,
		zeroParticipant:      nil,
		trustedDealerID:      trustedDealerID,
		prevShareholders:     prevShareholders,
		prevUnanimity:        prevUnanimity,
		prevShard:            prevShard,
		nextAccessStructures: nextAccessStructure,
		prng:                 prng,
		//nolint:exhaustruct // state is lazily initialised
		state: state[G, S]{
			round: 1,
		},
	}

	if prevShareholders.Contains(ctx.HolderID()) {
		zeroCtx, err := ctx.SubContext(prevShareholders)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create subcontext")
		}
		zeroGroup := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](prevShard.PublicKeyValue().Structure())
		zeroParticipant, err := hjky.NewParticipant(zeroCtx, prevUnanimity, zeroGroup, prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create zero participant")
		}
		p.zeroParticipant = zeroParticipant
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

func (*Participant[G, S]) mspSharingScheme(group algebra.PrimeGroup[G, S], mspMatrix *msp.MSP[S]) (*feldman.Scheme[G, S], error) {
	kwScheme, err := kw.NewInducedScheme(mspMatrix)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create KW sharing scheme")
	}
	sharingScheme, err := feldman.NewSchemeFromKW(group, kwScheme)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create feldman sharing scheme")
	}

	return sharingScheme, nil
}

func (*Participant[G, S]) acSharingScheme(group algebra.PrimeGroup[G, S], ac accessstructures.Monotone) (*feldman.Scheme[G, S], error) {
	sharingScheme, err := feldman.NewScheme(group, ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create feldman sharing scheme")
	}

	return sharingScheme, nil
}
