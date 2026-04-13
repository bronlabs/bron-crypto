package bls

import (
	"sync"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	mpcsig "github.com/bronlabs/bron-crypto/pkg/mpc/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

// PublicMaterial contains the public cryptographic material for an MPC BLS signature scheme
// over an arbitrary monotone access structure. It holds the combined public key, the MSP matrix
// induced from the access structure, the Feldman verification vector, and the partial public keys
// for each party. The type parameters support pairing-friendly curves where PK is the public key
// group and SG is the signature group.
type PublicMaterial[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	mpc.BasePublicMaterial[PK, S]

	pk     *bls.PublicKey[PK, PKFE, SG, SGFE, E, S]
	pkOnce sync.Once
}

type publicMaterialDTO[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	Base *mpc.BasePublicMaterial[PK, S] `cbor:"base"`
}

// PublicKey returns the combined BLS public key for the scheme.
// Returns nil if the receiver is nil or if the underlying public key value is invalid.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) PublicKey() *bls.PublicKey[PK, PKFE, SG, SGFE, E, S] {
	if spm == nil {
		return nil
	}
	spm.pkOnce.Do(func() {
		spm.pk, _ = bls.NewPublicKey(spm.PublicKeyValue())
	})
	return spm.pk
}

// Equal returns true if two PublicMaterial instances are equal.
// Two instances are equal if they have the same access structure, public key,
// and identical partial public keys for all parties.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) Equal(other *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) bool {
	if spm == nil || other == nil {
		return spm == other
	}
	return spm.BasePublicMaterial.Equal(&other.BasePublicMaterial)
}

// HashCode returns a hash code for the public material, derived from the public key.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) HashCode() base.HashCode {
	if spm == nil {
		return 0
	}
	return spm.PublicKeyValue().HashCode()
}

// MarshalCBOR serialises public material.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) MarshalCBOR() ([]byte, error) {
	dto := &publicMaterialDTO[PK, PKFE, SG, SGFE, E, S]{
		Base: &spm.BasePublicMaterial,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal public material to CBOR")
	}
	return data, nil
}

// UnmarshalCBOR deserialises public material.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*publicMaterialDTO[PK, PKFE, SG, SGFE, E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal public material from CBOR")
	}
	if dto == nil {
		return ErrIsNil.WithMessage("unmarshalled public material DTO is nil")
	}
	if dto.Base == nil {
		return ErrIsNil.WithMessage("missing required field in public material")
	}

	spm.BasePublicMaterial = *dto.Base
	return nil
}

// Shard represents a party's secret share in an MPC BLS signature scheme over an arbitrary
// monotone access structure. It embeds PublicMaterial and additionally contains the party's
// private Feldman share, which is used to produce partial signatures. Shards should be kept
// secret by their owners.
type Shard[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	mpc.BaseShard[PK, S]

	pk     *bls.PublicKey[PK, PKFE, SG, SGFE, E, S]
	pkOnce sync.Once
}

type shardDTO[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	Base *mpc.BaseShard[PK, S] `cbor:"base"`
}

// PublicKey returns the BLS public key associated with the shard.
// Returns nil if the receiver is nil or if the underlying public key value is invalid.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) PublicKey() *bls.PublicKey[PK, PKFE, SG, SGFE, E, S] {
	if s == nil {
		return nil
	}
	s.pkOnce.Do(func() {
		s.pk, _ = bls.NewPublicKey(s.PublicKeyValue())
	})
	return s.pk
}

// HashCode returns a hash code for the shard, derived from both the share and public key.
// Returns 0 if the receiver is nil.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) HashCode() base.HashCode {
	if s == nil {
		return 0
	}
	acc := s.PublicKeyValue().HashCode()
	for _, si := range s.Share().Value() {
		acc = acc.Combine(si.HashCode())
	}
	return acc
}

// Equal returns true if this shard equals another shard.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) Equal(other mpcsig.Shard[*bls.PublicKey[PK, PKFE, SG, SGFE, E, S], *feldman.Share[S]]) bool {
	if s == nil || other == nil {
		return s == other
	}
	o, ok := other.(*Shard[PK, PKFE, SG, SGFE, E, S])
	return ok && s.BaseShard.Equal(&o.BaseShard)
}

// PublicKeyMaterial extracts and returns a copy of the public material from the shard.
// The returned PublicMaterial can be safely shared with other parties.
// Returns nil if the receiver is nil.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) PublicKeyMaterial() *PublicMaterial[PK, PKFE, SG, SGFE, E, S] {
	if s == nil {
		return nil
	}

	return &PublicMaterial[PK, PKFE, SG, SGFE, E, S]{ //nolint:exhaustruct // BasePublicMaterial is lazily initialised.
		BasePublicMaterial: s.BasePublicMaterial,
	}
}

// MarshalCBOR serialises shard.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) MarshalCBOR() ([]byte, error) {
	if s == nil {
		return nil, ErrIsNil.WithMessage("cannot marshal nil shard")
	}
	dto := &shardDTO[PK, PKFE, SG, SGFE, E, S]{
		Base: &s.BaseShard,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal shard to CBOR")
	}
	return data, nil
}

// UnmarshalCBOR deserialises shard.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) UnmarshalCBOR(data []byte) error {
	if s == nil {
		return ErrIsNil.WithMessage("cannot unmarshal into nil shard")
	}
	dto, err := serde.UnmarshalCBOR[*shardDTO[PK, PKFE, SG, SGFE, E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal shard from CBOR")
	}
	if dto == nil {
		return ErrIsNil.WithMessage("unmarshalled shard DTO is nil")
	}
	if dto.Base == nil {
		return ErrIsNil.WithMessage("missing required field in shard")
	}
	s.BaseShard = *dto.Base
	return nil
}

// NewShortKeyShard creates a new Shard for the short key variant of BLS signatures.
// In the short key variant, public keys are in G1 (shorter) and signatures are in G2 (longer).
// This provides smaller public keys at the cost of larger signatures.
//
// The short/long variant is inferred from the type parameters: the public key
// group's base field FE1 must be a prime field for the short variant.
//
// Parameters:
//   - share: The party's Feldman share of the secret key
//   - vector: The Feldman verification vector
//   - mspMatrix: The MSP matrix induced from the access structure
//
// Returns an error if any parameter is nil or if base shard construction fails.
func NewShortKeyShard[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.PrimeFieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	share *feldman.Share[S],
	vector *feldman.VerificationVector[P1, S],
	mspMatrix *msp.MSP[S],
) (*Shard[P1, FE1, P2, FE2, E, S], error) {
	if share == nil {
		return nil, ErrIsNil.WithMessage("share")
	}
	if mspMatrix == nil {
		return nil, ErrIsNil.WithMessage("mspMatrix")
	}
	if vector == nil {
		return nil, ErrIsNil.WithMessage("verification vector")
	}

	baseShard, err := mpc.NewBaseShard(share, vector, mspMatrix)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create base shard")
	}

	return &Shard[P1, FE1, P2, FE2, E, S]{ //nolint:exhaustruct // BaseShard is lazily initialised.
		BaseShard: *baseShard,
	}, nil
}

// NewLongKeyShard creates a new Shard for the long key variant of BLS signatures.
// In the long key variant, public keys are in G2 (longer) and signatures are in G1 (shorter).
// This provides smaller signatures at the cost of larger public keys.
//
// The short/long variant is inferred from the type parameters: the signature
// group's base field FE1 must be a prime field for the long variant.
//
// Parameters:
//   - share: The party's Feldman share of the secret key
//   - vector: The Feldman verification vector
//   - mspMatrix: The MSP matrix induced from the access structure
//
// Returns an error if any parameter is nil or if base shard construction fails.
func NewLongKeyShard[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.PrimeFieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	share *feldman.Share[S],
	vector *feldman.VerificationVector[P2, S],
	mspMatrix *msp.MSP[S],
) (*Shard[P2, FE2, P1, FE1, E, S], error) {
	if share == nil {
		return nil, ErrIsNil.WithMessage("share")
	}
	if mspMatrix == nil {
		return nil, ErrIsNil.WithMessage("mspMatrix")
	}
	if vector == nil {
		return nil, ErrIsNil.WithMessage("verification vector")
	}

	baseShard, err := mpc.NewBaseShard(share, vector, mspMatrix)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create base shard")
	}

	return &Shard[P2, FE2, P1, FE1, E, S]{ //nolint:exhaustruct // BaseShard is lazily initialised.
		BaseShard: *baseShard,
	}, nil
}

var (
	// ErrIsNil is returned when a required input is nil.
	ErrIsNil = errs.New("is nil")
	// ErrInvalidArgument is returned when an input is invalid or inconsistent.
	ErrInvalidArgument = errs.New("invalid argument")
)
