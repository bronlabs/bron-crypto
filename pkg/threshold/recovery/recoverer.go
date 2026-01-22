package recovery

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
	"github.com/bronlabs/errs-go/errs"
)

// Recoverer orchestrates recovery of a missing party's share.
type Recoverer[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	shard      *tsig.BaseShard[G, S]
	scheme     *feldman.Scheme[G, S]
	group      algebra.PrimeGroup[G, S]
	field      algebra.PrimeField[S]
	mislayerID sharing.ID
	quorum     ds.Set[sharing.ID]
	prng       io.Reader
	state      RecovererState[G, S]
}

// RecovererState stores per-session randomness and blinded share data.
type RecovererState[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	blindShare *feldman.Share[S]
}

// NewRecoverer creates a recoverer that helps reconstruct the mislayer's share.
func NewRecoverer[
	G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S],
](mislayerID sharing.ID, quorum network.Quorum, shard *tsig.BaseShard[G, S], prng io.Reader) (*Recoverer[G, S], error) {
	if quorum == nil || shard == nil || !quorum.Contains(shard.Share().ID()) || !quorum.Contains(mislayerID) || !quorum.IsSubSet(shard.AccessStructure().Shareholders()) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](shard.VerificationVector().Coefficients()[0].Structure())
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](shard.Share().Value().Structure())
	scheme, err := feldman.NewScheme(group.Generator(), shard.AccessStructure().Threshold(), shard.AccessStructure().Shareholders())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create feldman scheme")
	}

	r := &Recoverer[G, S]{
		shard:      shard,
		scheme:     scheme,
		group:      group,
		field:      field,
		mislayerID: mislayerID,
		quorum:     quorum,
		prng:       prng,
		state:      RecovererState[G, S]{blindShare: nil},
	}
	return r, nil
}

// SharingID returns the identifier of the share being recovered.
func (r *Recoverer[G, S]) SharingID() sharing.ID {
	return r.shard.Share().ID()
}
