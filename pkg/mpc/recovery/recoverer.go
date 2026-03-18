package recovery

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
)

// Recoverer orchestrates recovery of a missing party's share.
type Recoverer[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	participant[G, S]
	recoverersCtx *session.Context
	shard         *tsig.BaseShard[G, S]
	group         algebra.PrimeGroup[G, S]
	mislayerID    sharing.ID
	prng          io.Reader
	state         RecovererState[G, S]
}

// RecovererState stores per-session randomness and blinded share data.
type RecovererState[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	blindShare *feldman.Share[S]
}

// NewRecoverer creates a recoverer that helps reconstruct the mislayer's share.
func NewRecoverer[
	G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S],
](ctx *session.Context, mislayerID sharing.ID, shard *tsig.BaseShard[G, S], prng io.Reader) (*Recoverer[G, S], error) {
	if ctx == nil || shard == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}

	quorum := ctx.Quorum()
	recoverers := quorum.Clone().Unfreeze()
	recoverers.Remove(mislayerID)
	if ctx.HolderID() != shard.Share().ID() || !quorum.Contains(mislayerID) || !quorum.IsSubSet(shard.AccessStructure().Shareholders()) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}
	recoverersCtx, err := ctx.SubContext(recoverers.Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create recoverers sub-context")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](shard.VerificationVector().Coefficients()[0].Structure())
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](shard.Share().Value().Structure())
	scheme, err := feldman.NewScheme(group.Generator(), shard.AccessStructure())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create feldman scheme")
	}

	r := &Recoverer[G, S]{
		participant: participant[G, S]{
			ctx:    ctx,
			field:  field,
			scheme: scheme,
		},
		recoverersCtx: recoverersCtx,
		shard:         shard,
		group:         group,
		mislayerID:    mislayerID,
		prng:          prng,
		state:         RecovererState[G, S]{blindShare: nil},
	}
	return r, nil
}

// SharingID returns the identifier of the share being recovered.
func (r *Recoverer[G, S]) SharingID() sharing.ID {
	return r.ctx.HolderID()
}
