package tbls

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/errs-go/pkg/errs"
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
	publicKey         *bls.PublicKey[PK, PKFE, SG, SGFE, E, S]
	accessStructure   *sharing.ThresholdAccessStructure
	fv                *feldman.VerificationVector[PK, S]
	partialPublicKeys ds.Map[sharing.ID, *bls.PublicKey[PK, PKFE, SG, SGFE, E, S]]
}

// PublicKey returns the combined BLS public key for the threshold scheme.
// Returns nil if the receiver is nil.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) PublicKey() *bls.PublicKey[PK, PKFE, SG, SGFE, E, S] {
	if spm == nil {
		return nil
	}
	return spm.publicKey
}

// AccessStructure returns the threshold access structure defining which subsets of parties
// are authorized to produce valid signatures. Returns nil if the receiver is nil.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) AccessStructure() *sharing.ThresholdAccessStructure {
	if spm == nil {
		return nil
	}
	return spm.accessStructure
}

// PartialPublicKeys returns the map of partial public keys indexed by party ID.
// Each partial public key can be used to verify partial signatures from the corresponding party.
// Returns nil if the receiver is nil.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) PartialPublicKeys() ds.Map[sharing.ID, *bls.PublicKey[PK, PKFE, SG, SGFE, E, S]] {
	if spm == nil {
		return nil
	}
	return spm.partialPublicKeys
}

// VerificationVector returns the Feldman verification vector used to verify
// that parties hold valid shares of the secret key. Returns nil if the receiver is nil.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) VerificationVector() *feldman.VerificationVector[PK, S] {
	if spm == nil {
		return nil
	}
	return spm.fv
}

// Equal returns true if two PublicMaterial instances are equal.
// Two instances are equal if they have the same access structure, public key,
// and identical partial public keys for all parties.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) Equal(other *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) bool {
	if spm == nil || other == nil {
		return spm == other
	}
	if !spm.accessStructure.Equal(other.accessStructure) {
		return false
	}
	if !spm.publicKey.Equal(other.publicKey) {
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

// HashCode returns a hash code for the public material, derived from the public key.
// Returns 0 if the receiver is nil.
func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) HashCode() base.HashCode {
	if spm == nil {
		return 0
	}
	return spm.publicKey.HashCode()
}

// Shard represents a party's secret share in a threshold BLS signature scheme.
// It embeds PublicMaterial and additionally contains the party's private Feldman share,
// which is used to produce partial signatures. Shards should be kept secret by their owners.
type Shard[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	PublicMaterial[PK, PKFE, SG, SGFE, E, S]

	share *feldman.Share[S]
}

// Share returns the party's Feldman share of the secret key.
// This share is used to compute partial signatures. Returns nil if the receiver is nil.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) Share() *feldman.Share[S] {
	if s == nil {
		return nil
	}
	return s.share
}

// Equal returns true if two Shard instances are equal.
// Two shards are equal if they have the same share and public material.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) Equal(other *Shard[PK, PKFE, SG, SGFE, E, S]) bool {
	if s == nil && other == nil {
		return s == other
	}
	return (s.share.Equal(other.share) &&
		s.PublicMaterial.Equal(&other.PublicMaterial))
}

// PublicKeyMaterial extracts and returns a copy of the public material from the shard.
// The returned PublicMaterial can be safely shared with other parties.
// Returns nil if the receiver is nil.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) PublicKeyMaterial() *PublicMaterial[PK, PKFE, SG, SGFE, E, S] {
	if s == nil {
		return nil
	}
	return &PublicMaterial[PK, PKFE, SG, SGFE, E, S]{
		publicKey:         s.publicKey.Clone(),
		accessStructure:   s.accessStructure.Clone(),
		fv:                s.fv,
		partialPublicKeys: s.partialPublicKeys.Clone(),
	}
}

// HashCode returns a hash code for the shard, derived from both the share and public key.
// Returns 0 if the receiver is nil.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) HashCode() base.HashCode {
	if s == nil {
		return 0
	}
	return s.share.HashCode() ^ s.publicKey.HashCode()
}

// AsBLSPrivateKey converts the shard to a BLS private key.
// This is useful for signing operations where the shard holder can produce partial signatures.
// Returns an error if the shard is nil or if the private key creation fails.
func (s *Shard[PK, PKFE, SG, SGFE, E, S]) AsBLSPrivateKey() (*bls.PrivateKey[PK, PKFE, SG, SGFE, E, S], error) {
	if s == nil {
		return nil, ErrIsNil.WithMessage("Shard is nil")
	}
	out, err := bls.NewPrivateKey(s.publicKey.Group(), s.share.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS private key from shard")
	}
	return out, nil
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
	accessStructure *sharing.ThresholdAccessStructure,
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
	sf, ok := share.Value().Structure().(algebra.PrimeField[S])
	if !ok {
		return nil, ErrInvalidArgument.WithMessage("share value structure is not a prime field")
	}
	partialPublicKeyValues, err := gennaro.ComputePartialPublicKey(sf, share, vector, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute partial public keys from share")
	}
	partialPublicKeys := hashmap.NewComparable[sharing.ID, *bls.PublicKey[P1, FE1, P2, FE2, E, S]]()
	for id, value := range partialPublicKeyValues.Iter() {
		pk, err := bls.NewPublicKey(value)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create public key for party %d", id)
		}
		partialPublicKeys.Put(id, pk)
	}
	return &Shard[P1, FE1, P2, FE2, E, S]{
		share: share,
		PublicMaterial: PublicMaterial[P1, FE1, P2, FE2, E, S]{
			publicKey:         publicKey,
			accessStructure:   accessStructure,
			fv:                &vector,
			partialPublicKeys: partialPublicKeys.Freeze(),
		},
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
	accessStructure *sharing.ThresholdAccessStructure,
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
	sf, ok := share.Value().Structure().(algebra.PrimeField[S])
	if !ok {
		return nil, ErrInvalidArgument.WithMessage("share value structure is not a prime field")
	}
	partialPublicKeyValues, err := gennaro.ComputePartialPublicKey(sf, share, vector, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute partial public keys from share")
	}
	partialPublicKeys := hashmap.NewComparable[sharing.ID, *bls.PublicKey[P2, FE2, P1, FE1, E, S]]()
	for id, value := range partialPublicKeyValues.Iter() {
		pk, err := bls.NewPublicKey(value)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create public key for party %d", id)
		}
		partialPublicKeys.Put(id, pk)
	}
	return &Shard[P2, FE2, P1, FE1, E, S]{
		share: share,
		PublicMaterial: PublicMaterial[P2, FE2, P1, FE1, E, S]{
			publicKey:         publicKey,
			accessStructure:   accessStructure,
			fv:                &vector,
			partialPublicKeys: partialPublicKeys.Freeze(),
		},
	}, nil
}

var (
	ErrIsNil           = errs.New("is nil")
	ErrInvalidArgument = errs.New("invalid argument")
)
