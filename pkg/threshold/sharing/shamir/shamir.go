package shamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
)

type (
	DealerFunc[FE algebra.PrimeFieldElement[FE]] = *polynomials.Polynomial[FE]
)

const Name sharing.Name = "Shamir's Secret Sharing"

func SharingIDToLagrangeNode[FE algebra.PrimeFieldElement[FE]](f algebra.PrimeField[FE], id sharing.ID) FE {
	return f.FromUint64(uint64(id))
}

func LagrangeCoefficients[FE algebra.PrimeFieldElement[FE]](field algebra.PrimeField[FE], sharingIds ...sharing.ID) (ds.Map[sharing.ID, FE], error) {
	if hashset.NewComparable(sharingIds...).Size() != len(sharingIds) {
		return nil, errs.NewMembership("invalid sharing id hash set")
	}

	sharingIdsScalar := make([]FE, len(sharingIds))
	for i, id := range sharingIds {
		sharingIdsScalar[i] = SharingIDToLagrangeNode(field, id)
	}

	basisPolynomials, err := interpolation.BasisAt(sharingIdsScalar, field.Zero())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute all basis polynomials at x=0")
	}

	result := hashmap.NewComparable[sharing.ID, FE]()
	for i, li := range basisPolynomials {
		result.Put(sharingIds[i], li)
	}

	return result.Freeze(), nil
}

// TODO: move outside of shamir (access structure is not something specific to shamir sharing)
type AccessStructure struct {
	t  uint
	ps ds.Set[sharing.ID]
}

type accessStructureDTO struct {
	T  uint                `cbor:"threshold"`
	Ps map[sharing.ID]bool `cbor:"shareholders"`
}

// TODO: this should be NewThresholdAccessStructure and should be in sharing package
func NewAccessStructure(t uint, ps ds.Set[sharing.ID]) (*AccessStructure, error) {
	if ps == nil {
		return nil, errs.NewIsNil("party set is nil")
	}
	if t < 2 {
		return nil, errs.NewValue("threshold cannot be less than 2")
	}
	if t > uint(ps.Size()) {
		return nil, errs.NewValue("total cannot be less than threshold")
	}
	return &AccessStructure{
		t:  t,
		ps: ps,
	}, nil
}

func (a *AccessStructure) Threshold() uint {
	return a.t
}

func (a *AccessStructure) Shareholders() ds.Set[sharing.ID] {
	return a.ps
}

func (a *AccessStructure) IsAuthorized(ids ...sharing.ID) bool {
	idsSet := hashset.NewComparable(ids...)
	return idsSet.Size() >= int(a.t) &&
		idsSet.Size() <= int(a.ps.Size()) &&
		idsSet.Freeze().IsSubSet(a.ps)
}

func (a *AccessStructure) Equal(other *AccessStructure) bool {
	if a == nil || other == nil {
		return a == other
	}
	if a.t != other.t {
		return false
	}
	if a.ps.Size() != other.ps.Size() {
		return false
	}
	return a.ps.Equal(other.ps)
}

func (a *AccessStructure) Clone() *AccessStructure {
	if a == nil {
		return nil
	}
	return &AccessStructure{
		t:  a.t,
		ps: a.ps.Clone(),
	}
}

func (a *AccessStructure) MarshalCBOR() ([]byte, error) {
	dto := &accessStructureDTO{
		T:  a.t,
		Ps: make(map[sharing.ID]bool),
	}
	for p := range a.ps.Iter() {
		dto.Ps[p] = true
	}

	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal AccessStructure")
	}
	return data, nil
}

func (a *AccessStructure) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*accessStructureDTO](data)
	if err != nil {
		return err
	}
	ps := hashset.NewComparable[sharing.ID]()
	for k, v := range dto.Ps {
		if v {
			ps.Add(k)
		}
	}
	a2, err := NewAccessStructure(dto.T, ps.Freeze())
	if err != nil {
		return err
	}

	*a = *a2
	return nil
}

func _[FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.DealerOutput[*Share[FE]]                                               = (*DealerOutput[FE])(nil)
		_ sharing.LinearShare[*Share[FE], FE, *additive.Share[FE], FE, *AccessStructure] = (*Share[FE])(nil)
		_ sharing.LinearlyShareableSecret[*Secret[FE], FE]                               = (*Secret[FE])(nil)

		_ sharing.ThresholdSSS[*Share[FE], *Secret[FE], *DealerOutput[FE], *AccessStructure]
		_ sharing.PolynomialLSSS[*Share[FE], FE, *additive.Share[FE], *Secret[FE], FE, *DealerOutput[FE], *AccessStructure] = (*Scheme[FE])(nil)
	)
}
