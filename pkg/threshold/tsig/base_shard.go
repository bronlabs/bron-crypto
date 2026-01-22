package tsig

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

// BasePublicMaterial contains the public information for threshold signature verification,
// including the access structure, verification vector, and partial public keys for each party.
type BasePublicMaterial[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	accessStructure   *sharing.ThresholdAccessStructure
	fv                feldman.VerificationVector[E, S]
	partialPublicKeys ds.Map[sharing.ID, *schnorrlike.PublicKey[E, S]]
}

type basePublicMaterialDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	AccessStructure   *sharing.ThresholdAccessStructure           `cbor:"accessStructure"`
	FV                feldman.VerificationVector[E, S]            `cbor:"verificationVector"`
	PartialPublicKeys map[sharing.ID]*schnorrlike.PublicKey[E, S] `cbor:"partialPublicKeys"`
}

// AccessStructure returns the threshold access structure defining authorized quorums.
func (spm *BasePublicMaterial[E, S]) AccessStructure() *sharing.ThresholdAccessStructure {
	if spm == nil {
		return nil
	}
	return spm.accessStructure
}

// PublicKey returns the threshold public key (first coefficient of the verification vector).
func (spm *BasePublicMaterial[E, S]) PublicKey() E {
	return spm.fv.Coefficients()[0]
}

// PartialPublicKeys returns the map of party IDs to their partial public keys.
func (spm *BasePublicMaterial[E, S]) PartialPublicKeys() ds.Map[sharing.ID, *schnorrlike.PublicKey[E, S]] {
	if spm == nil {
		return nil
	}
	return spm.partialPublicKeys
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
	if spm.partialPublicKeys.Size() != other.partialPublicKeys.Size() {
		return false
	}
	for id, pk := range spm.partialPublicKeys.Iter() {
		otherPk, exists := other.partialPublicKeys.Get(id)
		if !exists || !pk.Equal(otherPk) {
			return false
		}
	}

	return true
}

// HashCode returns a hash code for this public material.
func (spm *BasePublicMaterial[E, S]) HashCode() base.HashCode {
	return spm.fv.HashCode()
}

// MarshalCBOR serialises the public material to CBOR format.
func (spm *BasePublicMaterial[E, S]) MarshalCBOR() ([]byte, error) {
	ppk := make(map[sharing.ID]*schnorrlike.PublicKey[E, S])
	for k, v := range spm.partialPublicKeys.Iter() {
		ppk[k] = v
	}

	dto := &basePublicMaterialDTO[E, S]{
		AccessStructure:   spm.accessStructure,
		FV:                spm.fv,
		PartialPublicKeys: ppk,
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
		return err
	}

	ppk := hashmap.NewImmutableComparableFromNativeLike(dto.PartialPublicKeys)
	spm2 := &BasePublicMaterial[E, S]{
		accessStructure:   dto.AccessStructure,
		fv:                dto.FV,
		partialPublicKeys: ppk,
	}
	*spm = *spm2
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

// NewBaseShard creates a new base shard from a Feldman share, verification vector, and access structure.
// It computes the partial public keys for all parties in the access structure.
func NewBaseShard[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	share *feldman.Share[S],
	fv feldman.VerificationVector[E, S],
	accessStructure *sharing.ThresholdAccessStructure,
) (*BaseShard[E, S], error) {
	if share == nil || fv == nil || accessStructure == nil {
		return nil, ErrInvalidArgument.WithMessage("nil input parameters")
	}
	sf, ok := share.Value().Structure().(algebra.PrimeField[S])
	if !ok {
		return nil, ErrInvalidArgument.WithMessage("share value structure is not a prime field")
	}
	partialPublicKeyValues, err := gennaro.ComputePartialPublicKey(sf, share, fv, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute partial public keys from share")
	}
	partialPublicKeys := hashmap.NewComparable[sharing.ID, *schnorrlike.PublicKey[E, S]]()
	for id, value := range partialPublicKeyValues.Iter() {
		pk, err := schnorrlike.NewPublicKey(value)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create public key for party %d", id)
		}
		partialPublicKeys.Put(id, pk)
	}

	return &BaseShard[E, S]{
		share: share,
		BasePublicMaterial: BasePublicMaterial[E, S]{
			accessStructure:   accessStructure,
			fv:                fv,
			partialPublicKeys: partialPublicKeys.Freeze(),
		},
	}, nil
}

var (
	// ErrInvalidArgument is returned when a function receives an invalid argument.
	ErrInvalidArgument = errs.New("invalid argument")
)
