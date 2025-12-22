package recovery

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

// Mislayer represents the party whose share is being reconstructed.
type Mislayer[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	sharingId sharing.ID
	field     algebra.PrimeField[S]
	scheme    *feldman.Scheme[G, S]
	quorum    network.Quorum
}

// NewMislayer constructs a mislayer helper used to validate and interpolate recovered shares.
func NewMislayer[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](id sharing.ID, quorum network.Quorum, as sharing.ThresholdAccessStructure, group algebra.PrimeGroup[G, S]) (*Mislayer[G, S], error) {
	if quorum == nil || as == nil || group == nil || !quorum.Contains(id) || !quorum.IsSubSet(as.Shareholders()) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	scheme, err := feldman.NewScheme(group.Generator(), as.Threshold(), as.Shareholders())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create feldman scheme")
	}

	m := &Mislayer[G, S]{
		sharingId: id,
		field:     field,
		scheme:    scheme,
		quorum:    quorum,
	}
	return m, nil
}

// SharingID returns the identifier of the share being recovered.
func (m *Mislayer[G, S]) SharingID() sharing.ID {
	return m.sharingId
}
