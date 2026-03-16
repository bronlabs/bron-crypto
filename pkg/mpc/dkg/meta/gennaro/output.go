package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/errs-go/errs"
)

type DKGOutput[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	DKGPublicOutput[E, S]

	share *kw.Share[S]
}

type DKGPublicOutput[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	publicKeyValue    E
	partialPublicKeys ds.Map[sharing.ID, *kw.LiftedShare[E, S]]
	fv                *feldman.VerificationVector[E, S]
	accessStructure   accessstructures.Linear
}

// Share returns the private KW share produced by the DKG.
func (o *DKGOutput[E, S]) Share() *kw.Share[S] {
	if o == nil {
		return nil
	}
	return o.share
}

// PublicMaterial returns a copy of the public output material.
func (o *DKGOutput[E, S]) PublicMaterial() *DKGPublicOutput[E, S] {
	if o == nil {
		return nil
	}
	return &DKGPublicOutput[E, S]{
		publicKeyValue:    o.publicKeyValue,
		partialPublicKeys: o.partialPublicKeys,
		fv:                o.fv,
		accessStructure:   o.accessStructure,
	}
}

// PublicKeyValue returns the joint public key value derived from the verification vector.
func (o *DKGPublicOutput[E, S]) PublicKeyValue() E {
	return o.publicKeyValue
}

// PartialPublicKeyValues returns the map of per-party public key contributions.
func (o *DKGPublicOutput[E, S]) PartialPublicKeyValues() ds.Map[sharing.ID, *kw.LiftedShare[E, S]] {
	if o == nil {
		return nil
	}
	return o.partialPublicKeys
}

// AccessStructure returns the access structure associated with the DKG output.
func (o *DKGPublicOutput[E, S]) AccessStructure() accessstructures.Linear {
	if o == nil {
		return nil
	}
	return o.accessStructure
}

// VerificationVector returns the Feldman verification vector committed during the protocol.
func (o *DKGPublicOutput[E, S]) VerificationVector() *feldman.VerificationVector[E, S] {
	if o == nil {
		return nil
	}
	return o.fv
}

func NewDKGOutput[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	sf algebra.PrimeField[S],
	share *kw.Share[S],
	ldf *kw.LiftedDealerFunc[E, S],
	accessStructure accessstructures.Linear,
) (*DKGOutput[E, S], error) {
	if share == nil {
		return nil, ErrInvalidArgument.WithMessage("share is nil")
	}
	if ldf == nil {
		return nil, ErrInvalidArgument.WithMessage("lifted dealer function is nil")
	}
	// TODO: add the column vector check to the deserializers of verification vectors
	if accessStructure == nil {
		return nil, ErrInvalidArgument.WithMessage("accessStructure is nil")
	}
	publicKeyValue := ldf.LiftedSecret().Value()
	partialPublicKeys := hashmap.NewComparable[sharing.ID, *kw.LiftedShare[E, S]]()
	for id := range accessStructure.Shareholders().Iter() {
		pki, err := ldf.ShareOf(id)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to compute partial public key for shareholder %d", id)
		}
		partialPublicKeys.Put(id, pki)
	}
	return &DKGOutput[E, S]{
		share: share,
		DKGPublicOutput: DKGPublicOutput[E, S]{
			publicKeyValue:    publicKeyValue,
			partialPublicKeys: partialPublicKeys.Freeze(),
			fv:                ldf.VerificationVector(),
			accessStructure:   accessStructure,
		},
	}, nil
}
