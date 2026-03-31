package mpc

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
)

// BasePublicMaterial holds the public artefacts common to all MPC protocols
// built on MSP-based Feldman VSS: the monotone span programme and the
// verification vector. From these two objects every other public quantity
// (aggregate public key, per-party public key shares) can be derived.
type BasePublicMaterial[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	msp *msp.MSP[S]
	fv  *feldman.VerificationVector[E, S]
}

type basePublicMaterialDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	MSP                *msp.MSP[S]                       `cbor:"msp"`
	VerificationVector *feldman.VerificationVector[E, S] `cbor:"verificationVector"`
}

// NewBasePublicMaterial creates a BasePublicMaterial from an MSP and a Feldman
// verification vector, validating that their dimensions are consistent.
func NewBasePublicMaterial[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	mspMatrix *msp.MSP[S],
	fv *feldman.VerificationVector[E, S],
) (*BasePublicMaterial[E, S], error) {
	if mspMatrix == nil || fv == nil {
		return nil, ErrInvalidArgument.WithMessage("nil input parameters")
	}
	rows, cols := fv.Value().Dimensions()
	if cols != 1 {
		return nil, ErrInvalidArgument.WithMessage("verification vector is not a column vector")
	}
	if rows != int(mspMatrix.D()) {
		return nil, ErrInvalidArgument.WithMessage("verification vector size does not match MSP size")
	}
	return &BasePublicMaterial[E, S]{
		msp: mspMatrix,
		fv:  fv,
	}, nil
}

// MSP returns the monotone span programme underlying this public material.
func (spm *BasePublicMaterial[E, S]) MSP() *msp.MSP[S] {
	return spm.msp
}

// PublicKeyValue derives and returns the aggregate public key group element
// from the verification vector and MSP.
func (spm *BasePublicMaterial[E, S]) PublicKeyValue() E {
	return errs.Must1(feldman.NewLiftedDealerFunc(spm.fv, spm.msp)).LiftedSecret().Value()
}

// PublicKeyShares derives and returns the per-party public key shares (lifted
// shares) from the verification vector and MSP.
func (spm *BasePublicMaterial[E, S]) PublicKeyShares() ds.Map[sharing.ID, *feldman.LiftedShare[E, S]] {
	df := errs.Must1(feldman.NewLiftedDealerFunc(spm.fv, spm.msp))

	pkShares := hashmap.NewComparable[sharing.ID, *feldman.LiftedShare[E, S]]()
	for shareholder := range spm.msp.Shareholders().Iter() {
		share, err := df.ShareOf(shareholder)
		if err != nil {
			panic(errs.Wrap(err).WithMessage("failed to derive public key share for shareholder %d", shareholder))
		}
		pkShares.Put(shareholder, share)
	}
	return pkShares.Freeze()
}

// VerificationVector returns the Feldman verification vector V = [r]G.
func (spm *BasePublicMaterial[E, S]) VerificationVector() *feldman.VerificationVector[E, S] {
	return spm.fv
}

// Equal reports whether two BasePublicMaterial values are identical.
func (spm *BasePublicMaterial[E, S]) Equal(other *BasePublicMaterial[E, S]) bool {
	if spm == nil || other == nil {
		return spm == other
	}
	if !spm.msp.Equal(other.msp) {
		return false
	}
	if !spm.fv.Equal(other.fv) {
		return false
	}
	return true
}

// HashCode returns a hash code for use in hash-based collections.
func (spm *BasePublicMaterial[E, S]) HashCode() base.HashCode {
	return spm.fv.HashCode().Combine(spm.msp.Matrix().HashCode())
}

// MarshalCBOR serialises the public material to CBOR.
func (spm *BasePublicMaterial[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &basePublicMaterialDTO[E, S]{
		MSP:                spm.msp,
		VerificationVector: spm.fv,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal BasePublicMaterial")
	}
	return data, nil
}

// UnmarshalCBOR deserialises public material from CBOR.
func (spm *BasePublicMaterial[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*basePublicMaterialDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal BasePublicMaterial")
	}
	out, err := NewBasePublicMaterial(dto.MSP, dto.VerificationVector)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create BasePublicMaterial from deserialized data")
	}
	spm.msp = out.msp
	spm.fv = out.fv
	return nil
}

// BaseShard combines BasePublicMaterial with a party's private Feldman share.
// It embeds the public material so every shard carrier also has access to the
// MSP, verification vector, aggregate public key, and per-party public key
// shares.
type BaseShard[
	E algebra.PrimeGroupElement[E, S],
	S algebra.PrimeFieldElement[S],
] struct {
	BasePublicMaterial[E, S]

	share *feldman.Share[S]
}

// NewBaseShard creates a BaseShard from a Feldman share, verification vector,
// and MSP. It validates that the share is consistent with the verification
// vector by lifting it and comparing against the VV-derived public key share.
func NewBaseShard[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	share *feldman.Share[S],
	fv *feldman.VerificationVector[E, S],
	mspMatrix *msp.MSP[S],
) (*BaseShard[E, S], error) {
	basePublicMaterial, err := NewBasePublicMaterial(mspMatrix, fv)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BasePublicMaterial for BaseShard")
	}
	if share == nil {
		return nil, ErrInvalidArgument.WithMessage("nil input parameters")
	}
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](fv.Value().Module().BaseModule())

	pks, exists := basePublicMaterial.PublicKeyShares().Get(share.ID())
	if !exists {
		return nil, ErrInvalidArgument.WithMessage("share ID does not correspond to any shareholder in the MSP")
	}
	manuallyLiftedShare, err := feldman.LiftShare(share, group.Generator())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to lift share to group element")
	}
	if !manuallyLiftedShare.Equal(pks) {
		return nil, ErrInvalidArgument.WithMessage("share value does not match public key share derived from verification vector")
	}

	return &BaseShard[E, S]{
		share:              share,
		BasePublicMaterial: *basePublicMaterial,
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
		return nil, errs.Wrap(err).WithMessage("failed to marshal BaseShard")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the shard from CBOR format.
func (sh *BaseShard[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*baseShardDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal BaseShard")
	}

	sh2, err := NewBaseShard(dto.Share, dto.PM.VerificationVector(), dto.PM.MSP())
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create BaseShard from deserialized data")
	}
	*sh = *sh2
	return nil
}
