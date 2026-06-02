package cggmp21

import (
	"maps"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// AuxInfo holds auxiliary information for the CGGMP21 signature scheme.
type AuxInfo struct {
	paillierSecretKey  *paillier.SecretKey
	paillierPublicKeys map[sharing.ID]*paillier.PublicKey

	ringPedersenSecretKey  *intcom.TrapdoorKey
	ringPedersenPublicKeys map[sharing.ID]*intcom.CommitmentKey
}

// NewAuxInfo constructs CGGMP21 auxiliary information.
func NewAuxInfo(
	paillierSecretKey *paillier.SecretKey,
	paillierPublicKeys map[sharing.ID]*paillier.PublicKey,
	ringPedersenSecretKey *intcom.TrapdoorKey,
	ringPedersenPublicKeys map[sharing.ID]*intcom.CommitmentKey,
) (*AuxInfo, error) {
	if err := validateAuxInfoShape(paillierSecretKey, paillierPublicKeys, ringPedersenSecretKey, ringPedersenPublicKeys); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid auxiliary information")
	}
	return &AuxInfo{
		paillierSecretKey:      paillierSecretKey,
		paillierPublicKeys:     maps.Clone(paillierPublicKeys),
		ringPedersenSecretKey:  ringPedersenSecretKey,
		ringPedersenPublicKeys: maps.Clone(ringPedersenPublicKeys),
	}, nil
}

// PaillierSecretKey returns the local Paillier secret key.
func (info *AuxInfo) PaillierSecretKey() *paillier.SecretKey {
	if info == nil {
		return nil
	}
	return info.paillierSecretKey
}

// PaillierPublicKeys returns the Paillier public keys indexed by sharing ID.
func (info *AuxInfo) PaillierPublicKeys() map[sharing.ID]*paillier.PublicKey {
	if info == nil {
		return nil
	}
	return maps.Clone(info.paillierPublicKeys)
}

// RingPedersenSecretKey returns the local ring-Pedersen trapdoor key.
func (info *AuxInfo) RingPedersenSecretKey() *intcom.TrapdoorKey {
	if info == nil {
		return nil
	}
	return info.ringPedersenSecretKey
}

// RingPedersenPublicKeys returns the ring-Pedersen public keys indexed by sharing ID.
func (info *AuxInfo) RingPedersenPublicKeys() map[sharing.ID]*intcom.CommitmentKey {
	if info == nil {
		return nil
	}
	return maps.Clone(info.ringPedersenPublicKeys)
}

// Equal reports whether two AuxInfo values contain the same keys.
func (info *AuxInfo) Equal(other *AuxInfo) bool {
	if info == nil || other == nil {
		return info == other
	}
	if !info.paillierSecretKey.Equal(other.paillierSecretKey) {
		return false
	}
	if !info.ringPedersenSecretKey.Equal(other.ringPedersenSecretKey) {
		return false
	}
	if !equalPaillierPublicKeys(info.paillierPublicKeys, other.paillierPublicKeys) {
		return false
	}
	return equalRingPedersenPublicKeys(info.ringPedersenPublicKeys, other.ringPedersenPublicKeys)
}

// Shard holds a CGGMP21 ECDSA key share and its auxiliary information.
type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	mpc.BaseShard[P, S]

	auxInfo *AuxInfo
}

// NewShard returns a new shard.
func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](baseShard *mpc.BaseShard[P, S], info *AuxInfo) (*Shard[P, B, S], error) {
	if baseShard == nil {
		return nil, ErrNil.WithMessage("base shard")
	}
	if baseShard.Share() == nil {
		return nil, ErrNil.WithMessage("base shard share")
	}
	if err := validateAuxInfoForShard(baseShard, info); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid auxiliary information")
	}

	sh := &Shard[P, B, S]{
		BaseShard: *baseShard,
		auxInfo:   info,
	}
	return sh, nil
}

// PublicKey returns the public key.
func (sh *Shard[P, B, S]) PublicKey() *sigecdsa.PublicKey[P, B, S] {
	pkValue := sh.PublicKeyValue()
	pk, err := sigecdsa.NewPublicKey(pkValue)
	if err != nil {
		panic(err) // this should never happen.
	}
	return pk
}

// AuxInfo returns the auxiliary information.
func (sh *Shard[P, B, S]) AuxInfo() *AuxInfo {
	return sh.auxInfo
}

// Equal returns true if the two shards are equal.
func (sh *Shard[P, B, S]) Equal(rhs *Shard[P, B, S]) bool {
	if sh == nil || rhs == nil {
		return sh == rhs
	}
	return sh.BaseShard.Equal(&rhs.BaseShard) && sh.auxInfo.Equal(rhs.auxInfo)
}

func validateAuxInfoShape(
	paillierSecretKey *paillier.SecretKey,
	paillierPublicKeys map[sharing.ID]*paillier.PublicKey,
	ringPedersenSecretKey *intcom.TrapdoorKey,
	ringPedersenPublicKeys map[sharing.ID]*intcom.CommitmentKey,
) error {
	if paillierSecretKey == nil || paillierSecretKey.Group() == nil {
		return ErrNil.WithMessage("paillier secret key")
	}
	if ringPedersenSecretKey == nil ||
		ringPedersenSecretKey.Group() == nil ||
		ringPedersenSecretKey.Lambda() == nil ||
		ringPedersenSecretKey.S() == nil ||
		ringPedersenSecretKey.T() == nil {

		return ErrNil.WithMessage("ring pedersen trapdoor key")
	}
	if len(paillierPublicKeys) == 0 {
		return ErrNil.WithMessage("paillier public keys")
	}
	if len(ringPedersenPublicKeys) == 0 {
		return ErrNil.WithMessage("ring pedersen public keys")
	}
	if len(paillierPublicKeys) != len(ringPedersenPublicKeys) {
		return ErrValidationFailed.WithMessage("public key maps must have the same size")
	}
	for id, publicKey := range paillierPublicKeys {
		if publicKey == nil || publicKey.Group() == nil {
			return ErrNil.WithMessage("paillier public key for %d", id)
		}
		ringPedersenPublicKey, ok := ringPedersenPublicKeys[id]
		if !ok {
			return ErrValidationFailed.WithMessage("missing ring pedersen public key for %d", id)
		}
		if err := validateRingPedersenPublicKey(id, ringPedersenPublicKey); err != nil {
			return errs.Wrap(err)
		}
	}
	return nil
}

func validateAuxInfoForShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](baseShard *mpc.BaseShard[P, S], info *AuxInfo) error {
	if info == nil {
		return ErrNil.WithMessage("auxiliary information")
	}
	shareholders := baseShard.MSP().Shareholders()
	if len(info.paillierPublicKeys) != shareholders.Size() {
		return ErrValidationFailed.WithMessage("paillier public key count does not match shareholders")
	}
	if len(info.ringPedersenPublicKeys) != shareholders.Size() {
		return ErrValidationFailed.WithMessage("ring pedersen public key count does not match shareholders")
	}
	for id := range shareholders.Iter() {
		if _, ok := info.paillierPublicKeys[id]; !ok {
			return ErrValidationFailed.WithMessage("missing paillier public key for %d", id)
		}
		if _, ok := info.ringPedersenPublicKeys[id]; !ok {
			return ErrValidationFailed.WithMessage("missing ring pedersen public key for %d", id)
		}
	}

	id := baseShard.Share().ID()
	paillierPublicKey, ok := info.paillierPublicKeys[id]
	if !ok {
		return ErrValidationFailed.WithMessage("missing local paillier public key")
	}
	if !info.paillierSecretKey.Public().Equal(paillierPublicKey) {
		return ErrValidationFailed.WithMessage("local paillier secret key does not match public key")
	}
	ringPedersenPublicKey, ok := info.ringPedersenPublicKeys[id]
	if !ok {
		return ErrValidationFailed.WithMessage("missing local ring pedersen public key")
	}
	if !info.ringPedersenSecretKey.Export().Equal(ringPedersenPublicKey) {
		return ErrValidationFailed.WithMessage("local ring pedersen trapdoor key does not match public key")
	}
	return nil
}

func validateRingPedersenPublicKey(id sharing.ID, publicKey *intcom.CommitmentKey) error {
	if publicKey == nil || publicKey.S() == nil || publicKey.T() == nil {
		return ErrNil.WithMessage("ring pedersen public key for %d", id)
	}
	if publicKey.Group() == nil {
		return ErrNil.WithMessage("ring pedersen public key group for %d", id)
	}
	return nil
}

func equalPaillierPublicKeys(lhs, rhs map[sharing.ID]*paillier.PublicKey) bool {
	if len(lhs) != len(rhs) {
		return false
	}
	for id, lhsKey := range lhs {
		rhsKey, ok := rhs[id]
		if !ok || !lhsKey.Equal(rhsKey) {
			return false
		}
	}
	return true
}

func equalRingPedersenPublicKeys(lhs, rhs map[sharing.ID]*intcom.CommitmentKey) bool {
	if len(lhs) != len(rhs) {
		return false
	}
	for id, lhsKey := range lhs {
		rhsKey, ok := rhs[id]
		if !ok || !lhsKey.Equal(rhsKey) {
			return false
		}
	}
	return true
}
