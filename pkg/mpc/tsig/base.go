package tsig

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
)

// BasePublicMaterial contains the public information for threshold signature verification,
// including the access structure, verification vector, and partial public keys for each party.
type BasePublicMaterial[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	accessStructure *threshold.Threshold
	fv              feldman.VerificationVector[E, S]
}

type basePublicMaterialDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	AccessStructure    *threshold.Threshold             `cbor:"accessStructure"`
	VerificationVector feldman.VerificationVector[E, S] `cbor:"verificationVector"`
}

// AccessStructure returns the threshold access structure defining authorized quorums.
func (spm *BasePublicMaterial[E, S]) AccessStructure() *threshold.Threshold {
	if spm == nil {
		return nil
	}
	return spm.accessStructure
}

// PublicKeyValue returns the threshold public key (first coefficient of the verification vector).
func (spm *BasePublicMaterial[E, S]) PublicKeyValue() E {
	return spm.fv.Coefficients()[0]
}

// PublicKeyValueShares returns the map of party IDs to their public key shares.
func (spm *BasePublicMaterial[E, S]) PublicKeyValueShares() ds.Map[sharing.ID, *feldman.LiftedShare[E, S]] {
	if spm == nil {
		return nil
	}

	return errs.Must1(DerivePublicKeyShares(spm.fv, spm.accessStructure.Shareholders()))
}

// VerificationVector returns the Feldman verification vector for the shared secret.
func (spm *BasePublicMaterial[E, S]) VerificationVector() feldman.VerificationVector[E, S] {
	if spm == nil {
		return nil
	}
	return spm.fv
}

// Equal returns true if this public material equals another.
func (spm *BasePublicMaterial[E, S]) Equal(other *BasePublicMaterial[E, S]) bool {
	if spm == nil || other == nil {
		return spm == other
	}
	if !spm.accessStructure.Equal(other.accessStructure) {
		return false
	}
	if !spm.fv.Equal(other.fv) {
		return false
	}

	return true
}

// HashCode returns a hash code for this public material.
func (spm *BasePublicMaterial[E, S]) HashCode() base.HashCode {
	return spm.fv.HashCode()
}

// MarshalCBOR serialises the public material to CBOR format.
func (spm *BasePublicMaterial[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &basePublicMaterialDTO[E, S]{
		AccessStructure:    spm.accessStructure,
		VerificationVector: spm.fv,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal tSchnorr BasePublicMaterial")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the public material from CBOR format.
func (spm *BasePublicMaterial[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*basePublicMaterialDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal BasePublicMaterial")
	}
	if dto.AccessStructure == nil || dto.VerificationVector == nil {
		return ErrInvalidArgument.WithMessage("nil input parameters")
	}
	if dto.VerificationVector.Degree() != int(dto.AccessStructure.Threshold())-1 {
		return ErrInvalidArgument.WithMessage("verification vector degree does not match access structure threshold")
	}

	spm.accessStructure = dto.AccessStructure
	spm.fv = dto.VerificationVector
	return nil
}

// BaseShard contains a party's secret share and the associated public material for threshold signing.
type BaseShard[
	E algebra.PrimeGroupElement[E, S],
	S algebra.PrimeFieldElement[S],
] struct {
	BasePublicMaterial[E, S]

	share *feldman.Share[S]
}

// NewBaseShard creates a new base shard from a Feldman share, verification vector, and access structure.
// It computes the partial public keys for all parties in the access structure.
func NewBaseShard[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	share *feldman.Share[S],
	fv feldman.VerificationVector[E, S],
	accessStructure *threshold.Threshold,
) (*BaseShard[E, S], error) {
	if share == nil || fv == nil || accessStructure == nil {
		return nil, ErrInvalidArgument.WithMessage("nil input parameters")
	}
	if fv.Degree() != int(accessStructure.Threshold())-1 {
		return nil, ErrInvalidArgument.WithMessage("verification vector degree does not match access structure threshold")
	}
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](fv.Coefficients()[0].Structure())
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	publicKeyShareValue := fv.Eval(field.FromUint64(uint64(share.ID())))
	if !publicKeyShareValue.Equal(group.ScalarBaseOp(share.Value())) {
		return nil, ErrInvalidArgument.WithMessage("share value does not match verification vector")
	}

	return &BaseShard[E, S]{
		share: share,
		BasePublicMaterial: BasePublicMaterial[E, S]{
			accessStructure: accessStructure,
			fv:              fv,
		},
	}, nil
}

type baseShardDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	Share *feldman.Share[S]        `cbor:"share"`
	PM    BasePublicMaterial[E, S] `cbor:"publicMaterial"`
}

// Share returns the party's Feldman secret share.
func (sh *BaseShard[E, S]) Share() *feldman.Share[S] {
	if sh == nil {
		return nil
	}
	return sh.share
}

// Equal returns true if this shard equals another.
func (sh *BaseShard[E, S]) Equal(other *BaseShard[E, S]) bool {
	if sh == nil || other == nil {
		return sh == other
	}
	return sh.share.Equal(other.share) &&
		sh.BasePublicMaterial.Equal(&other.BasePublicMaterial)
}

// HashCode returns a hash code for this shard.
func (sh *BaseShard[E, S]) HashCode() base.HashCode {
	if sh == nil {
		return base.HashCode(0)
	}
	return sh.BasePublicMaterial.HashCode()
}

// MarshalCBOR serialises the shard to CBOR format.
func (sh *BaseShard[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &baseShardDTO[E, S]{
		Share: sh.share,
		PM:    sh.BasePublicMaterial,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal tSchnorr BaseShard")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the shard from CBOR format.
func (sh *BaseShard[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*baseShardDTO[E, S]](data)
	if err != nil {
		return err
	}

	sh2, err := NewBaseShard(dto.Share, dto.PM.VerificationVector(), dto.PM.AccessStructure())
	if err != nil {
		return err
	}
	*sh = *sh2
	return nil
}

func DerivePublicKeyShares[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](verificationVector feldman.VerificationVector[E, S], shareholders ds.Set[sharing.ID]) (ds.Map[sharing.ID, *feldman.LiftedShare[E, S]], error) {
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](verificationVector.CoefficientStructure())
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	result := hashmap.NewComparable[sharing.ID, *feldman.LiftedShare[E, S]]()
	for id := range shareholders.Iter() {
		shareValue := verificationVector.Eval(field.FromUint64(uint64(id)))
		share, err := feldman.NewLiftedShare(id, shareValue)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create share")
		}
		result.Put(id, share)
	}

	return result.Freeze(), nil
}
