package tbls

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

// PublicMaterial contains the public cryptographic material for a threshold BLS signature scheme.
// It holds the combined public key, the access structure defining the threshold parameters,
// the Feldman verification vector, and the partial public keys for each party.
// The type parameters support pairing-friendly curves where PK is the public key group
// and SG is the signature group.
type PublicMaterial[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	tsig.BasePublicMaterial[PK, S]
}

type publicMaterialDTO[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	Base *tsig.BasePublicMaterial[PK, S] `cbor:"base"`
}

// PublicKey returns the combined BLS public key for the threshold scheme.
// Returns nil if the receiver is nil.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) PublicKey() *bls.PublicKey[PK, PKFE, SG, SGFE, E, S] {
	if spm == nil {
		return nil
	}
	pk, _ := bls.NewPublicKey(spm.PublicKeyValue())
	return pk
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
// Returns 0 if the receiver is nil.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) HashCode() base.HashCode {
	if spm == nil {
		return 0
	}
	return spm.PublicKeyValue().HashCode()
}

// MarshalCBOR serialises a shard.
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

// UnmarshalCBOR deserialises a shard.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*publicMaterialDTO[PK, PKFE, SG, SGFE, E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal public material from CBOR")
	}
	if dto.Base == nil {
		return ErrIsNil.WithMessage("missing required field in public material")
	}

	spm.BasePublicMaterial = *dto.Base
	if _, err := bls.NewPublicKey(spm.PublicKeyValue()); err != nil {
		return errs.Wrap(err).WithMessage("failed to create BLS public key from deserialized public material")
	}
	return nil
}

// Shard represents a party's secret share in a threshold BLS signature scheme.
// It embeds PublicMaterial and additionally contains the party's private Feldman share,
// which is used to produce partial signatures. Shards should be kept secret by their owners.
type Shard[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	tsig.BaseShard[PK, S]
}

type shardDTO[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	Base *tsig.BaseShard[PK, S] `cbor:"base"`
}

// PublicKey returns the BLS public key associated with the shard.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) PublicKey() *bls.PublicKey[PK, PKFE, SG, SGFE, E, S] {
	if s == nil {
		return nil
	}
	pk, _ := bls.NewPublicKey(s.PublicKeyValue())
	return pk
}

// Equal returns true if two Shard instances are equal.
// Two shards are equal if they have the same share and public material.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) Equal(other tsig.Shard[*bls.PublicKey[PK, PKFE, SG, SGFE, E, S], *feldman.Share[S], *threshold.Threshold]) bool {
	if s == nil || other == nil {
		return s == other
	}

	rhs, ok := other.(*Shard[PK, PKFE, SG, SGFE, E, S])
	if !ok {
		return false
	}

	return s.BaseShard.Equal(&rhs.BaseShard)
}

// HashCode returns a hash code for the shard, derived from both the share and public key.
// Returns 0 if the receiver is nil.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) HashCode() base.HashCode {
	if s == nil {
		return 0
	}
	return s.Share().Value().HashCode().Combine(s.PublicKeyValue().HashCode())
}

// PublicKeyMaterial extracts and returns a copy of the public material from the shard.
// The returned PublicMaterial can be safely shared with other parties.
// Returns nil if the receiver is nil.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) PublicKeyMaterial() *PublicMaterial[PK, PKFE, SG, SGFE, E, S] {
	if s == nil {
		return nil
	}

	return &PublicMaterial[PK, PKFE, SG, SGFE, E, S]{
		BasePublicMaterial: s.BasePublicMaterial,
	}
}

// AsPrivateKey converts the shard to a BLS private key share.
// This is useful for signing operations where the shard holder can produce partial signatures.
// Returns an error if the shard is nil or if the private key creation fails.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) AsPrivateKey() (*bls.PrivateKey[PK, PKFE, SG, SGFE, E, S], error) {
	if s == nil {
		return nil, ErrIsNil.WithMessage("Shard is nil")
	}
	publicKey := s.PublicKey()
	if publicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid public key material")
	}
	out, err := bls.NewPrivateKey(publicKey.Group(), s.Share().Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS private key from shard")
	}
	return out, nil
}

// AsAdditivePrivateKey converts the shard to an additive BLS private key share.
// This is useful for signing operations where the shard holder can produce partial signatures.
// Returns an error if the shard is nil or if the private key creation fails.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) AsAdditivePrivateKey(quorum *unanimity.Unanimity) (*bls.PrivateKey[PK, PKFE, SG, SGFE, E, S], error) {
	if s == nil {
		return nil, ErrIsNil.WithMessage("Shard is nil")
	}
	if !quorum.Shareholders().Contains(s.Share().ID()) {
		return nil, ErrInvalidArgument.WithMessage("id not in quorum")
	}
	if !s.AccessStructure().IsQualified(quorum.Shareholders().List()...) {
		return nil, ErrInvalidArgument.WithMessage("unqualified quorum")
	}

	additiveShare, err := s.Share().ToAdditive(quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert to additive")
	}
	publicKey := s.PublicKey()
	if publicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid public key material")
	}
	out, err := bls.NewPrivateKey(publicKey.Group(), additiveShare.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS private key from shard")
	}
	return out, nil
}

// MarshalCBOR serialises shard.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) MarshalCBOR() ([]byte, error) {
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
	dto, err := serde.UnmarshalCBOR[*shardDTO[PK, PKFE, SG, SGFE, E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal shard from CBOR")
	}
	if dto.Base == nil {
		return ErrIsNil.WithMessage("missing required field in shard")
	}

	s.BaseShard = *dto.Base
	if _, err := bls.NewPublicKey(s.PublicKeyValue()); err != nil {
		return errs.Wrap(err).WithMessage("failed to create BLS public key from deserialized shard")
	}
	return nil
}

// NewShortKeyShard creates a new Shard for the short key variant of BLS signatures.
// In the short key variant, public keys are in G1 (shorter) and signatures are in G2 (longer).
// This provides smaller public keys at the cost of larger signatures.
//
// Parameters:
//   - share: The party's Feldman share of the secret key
//   - publicKey: The combined BLS public key (must be a short key variant)
//   - vector: The Feldman verification vector
//   - accessStructure: The threshold access structure
//
// Returns an error if any parameter is nil, if the public key is not a short variant,
// or if partial public key computation fails.
func NewShortKeyShard[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](

	share *feldman.Share[S],
	publicKey *bls.PublicKey[P1, FE1, P2, FE2, E, S],
	vector feldman.VerificationVector[P1, S],
	accessStructure *threshold.Threshold,
) (*Shard[P1, FE1, P2, FE2, E, S], error) {
	if share == nil {
		return nil, ErrIsNil.WithMessage("share")
	}
	if publicKey == nil {
		return nil, ErrIsNil.WithMessage("publicKey")
	}
	if accessStructure == nil {
		return nil, ErrIsNil.WithMessage("accessStructure")
	}
	if vector == nil {
		return nil, ErrIsNil.WithMessage("verification vector")
	}
	if !publicKey.IsShort() {
		return nil, ErrInvalidArgument.WithMessage("public key is not a short key variant")
	}
	c := vector.Coefficients()
	if len(c) == 0 || !publicKey.Value().Equal(c[0]) {
		return nil, ErrInvalidArgument.WithMessage("public key does not match verification vector")
	}

	baseShard, err := tsig.NewBaseShard(share, vector, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create base shard")
	}

	return &Shard[P1, FE1, P2, FE2, E, S]{
		BaseShard: *baseShard,
	}, nil
}

// NewLongKeyShard creates a new Shard for the long key variant of BLS signatures.
// In the long key variant, public keys are in G2 (longer) and signatures are in G1 (shorter).
// This provides smaller signatures at the cost of larger public keys.
//
// Parameters:
//   - share: The party's Feldman share of the secret key
//   - publicKey: The combined BLS public key (must be a long key variant)
//   - vector: The Feldman verification vector
//   - accessStructure: The threshold access structure
//
// Returns an error if any parameter is nil, if the public key is not a long variant,
// or if partial public key computation fails.
func NewLongKeyShard[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	share *feldman.Share[S],
	publicKey *bls.PublicKey[P2, FE2, P1, FE1, E, S],
	vector feldman.VerificationVector[P2, S],
	accessStructure *threshold.Threshold,
) (*Shard[P2, FE2, P1, FE1, E, S], error) {
	if share == nil {
		return nil, ErrIsNil.WithMessage("share")
	}
	if publicKey == nil {
		return nil, ErrIsNil.WithMessage("publicKey")
	}
	if accessStructure == nil {
		return nil, ErrIsNil.WithMessage("accessStructure")
	}
	if vector == nil {
		return nil, ErrIsNil.WithMessage("verification vector")
	}
	if publicKey.IsShort() {
		return nil, ErrInvalidArgument.WithMessage("public key is not a long key variant")
	}
	if !publicKey.Value().Equal(vector.Coefficients()[0]) {
		return nil, ErrInvalidArgument.WithMessage("public key does not match verification vector")
	}

	baseShard, err := tsig.NewBaseShard(share, vector, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create base shard")
	}

	return &Shard[P2, FE2, P1, FE1, E, S]{
		BaseShard: *baseShard,
	}, nil
}

var (
	// ErrIsNil is returned when a required input is nil.
	ErrIsNil = errs.New("is nil")
	// ErrInvalidArgument is returned when an input is invalid or inconsistent.
	ErrInvalidArgument = errs.New("invalid argument")
)
