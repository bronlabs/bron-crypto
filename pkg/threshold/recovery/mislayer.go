package recovery

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

type Mislayer[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	sharingId sharing.ID
	field     algebra.PrimeField[S]
	scheme    *feldman.Scheme[G, S]
	quorum    network.Quorum
}

func NewMislayer[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](id sharing.ID, quorum network.Quorum, as sharing.ThresholdAccessStructure, group algebra.PrimeGroup[G, S]) (*Mislayer[G, S], error) {
	if quorum == nil || as == nil || group == nil || !quorum.Contains(id) || !quorum.IsSubSet(as.Shareholders()) {
		return nil, errs.NewValidation("invalid arguments")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	scheme, err := feldman.NewScheme(group.Generator(), as.Threshold(), as.Shareholders())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create feldman scheme")
	}

	m := &Mislayer[G, S]{
		sharingId: id,
		field:     field,
		scheme:    scheme,
		quorum:    quorum,
	}
	return m, nil
}

func (m *Mislayer[G, S]) SharingID() sharing.ID {
	return m.sharingId
}
