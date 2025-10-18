package recovery

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

type Recoverer[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	sharingId          sharing.ID
	share              *feldman.Share[S]
	verificationVector feldman.VerificationVector[G, S]
	as                 sharing.ThresholdAccessStructure
	scheme             *feldman.Scheme[G, S]
	group              algebra.PrimeGroup[G, S]
	field              algebra.PrimeField[S]
	mislayerId         sharing.ID
	quorum             ds.Set[sharing.ID]
	prng               io.Reader
	state              RecovererState[G, S]
}

type RecovererState[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	blindShare *feldman.Share[S]
}

func NewRecoverer[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](mislayerId sharing.ID, quorum network.Quorum, as sharing.ThresholdAccessStructure, share *feldman.Share[S], verificationVector feldman.VerificationVector[G, S], prng io.Reader) (*Recoverer[G, S], error) {
	if quorum == nil || as == nil || share == nil || !quorum.Contains(share.ID()) || !quorum.Contains(mislayerId) || !quorum.IsSubSet(as.Shareholders()) {
		return nil, errs.NewValidation("invalid arguments")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](verificationVector.Coefficients()[0].Structure())
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](share.Value().Structure())
	scheme, err := feldman.NewScheme(group.Generator(), as.Threshold(), as.Shareholders())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create feldman scheme")
	}

	r := &Recoverer[G, S]{
		sharingId:          share.ID(),
		share:              share,
		verificationVector: verificationVector,
		as:                 as,
		scheme:             scheme,
		group:              group,
		field:              field,
		mislayerId:         mislayerId,
		quorum:             quorum,
		prng:               prng,
		state:              RecovererState[G, S]{},
	}
	return r, nil
}

func (r *Recoverer[G, S]) SharingID() sharing.ID {
	return r.sharingId
}
