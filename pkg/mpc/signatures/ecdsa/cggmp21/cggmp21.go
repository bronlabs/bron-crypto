package cggmp21

import (
	"bytes"
	"maps"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
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

	refreshID []byte
}

type auxInfoDTO struct {
	PaillierSecretKey      *paillier.SecretKey                  `cbor:"paillierSecretKey"`
	PaillierPublicKeys     map[sharing.ID]*paillier.PublicKey   `cbor:"paillierPublicKeys"`
	RingPedersenSecretKey  *intcom.TrapdoorKey                  `cbor:"ringPedersenSecretKey"`
	RingPedersenPublicKeys map[sharing.ID]*intcom.CommitmentKey `cbor:"ringPedersenPublicKeys"`
	RefreshID              []byte                               `cbor:"refreshID"`
}

// NewAuxInfo constructs CGGMP21 auxiliary information.
func NewAuxInfo(
	paillierSecretKey *paillier.SecretKey,
	paillierPublicKeys map[sharing.ID]*paillier.PublicKey,
	ringPedersenSecretKey *intcom.TrapdoorKey,
	ringPedersenPublicKeys map[sharing.ID]*intcom.CommitmentKey,
	refreshID []byte,
) (*AuxInfo, error) {
	if paillierSecretKey == nil {
		return nil, ErrNil.WithMessage("paillier secret key")
	}
	if ringPedersenSecretKey == nil {
		return nil, ErrNil.WithMessage("ring pedersen trapdoor key")
	}
	if len(paillierPublicKeys) == 0 {
		return nil, ErrNil.WithMessage("paillier public keys")
	}
	if len(ringPedersenPublicKeys) == 0 {
		return nil, ErrNil.WithMessage("ring pedersen public keys")
	}
	if len(paillierPublicKeys) != len(ringPedersenPublicKeys) {
		return nil, ErrValidationFailed.WithMessage("public key maps must have the same size")
	}
	for id, publicKey := range paillierPublicKeys {
		if publicKey == nil {
			return nil, ErrNil.WithMessage("paillier public key for %d", id)
		}
		ringPedersenPublicKey, ok := ringPedersenPublicKeys[id]
		if !ok || ringPedersenPublicKey == nil {
			return nil, ErrNil.WithMessage("missing ring pedersen public key for %d", id)
		}
	}
	if len(refreshID) < base.CollisionResistanceBytesCeil {
		return nil, ErrNil.WithMessage("empty refresh ID")
	}

	info := &AuxInfo{
		paillierSecretKey:      paillierSecretKey,
		paillierPublicKeys:     maps.Clone(paillierPublicKeys),
		ringPedersenSecretKey:  ringPedersenSecretKey,
		ringPedersenPublicKeys: maps.Clone(ringPedersenPublicKeys),
		refreshID:              refreshID,
	}
	return info, nil
}

// MarshalCBOR serialises the auxiliary information. The output contains local
// Paillier and ring-Pedersen trapdoors and must be protected as secret material.
func (info *AuxInfo) MarshalCBOR() ([]byte, error) {
	if info == nil {
		return nil, ErrNil.WithMessage("auxiliary information")
	}
	dto := &auxInfoDTO{
		PaillierSecretKey:      info.paillierSecretKey,
		PaillierPublicKeys:     info.paillierPublicKeys,
		RingPedersenSecretKey:  info.ringPedersenSecretKey,
		RingPedersenPublicKeys: info.ringPedersenPublicKeys,
		RefreshID:              info.refreshID,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal auxiliary information to CBOR")
	}
	return data, nil
}

// UnmarshalCBOR deserialises auxiliary information and revalidates it via
// NewAuxInfo. This is a deserialisation trust boundary carrying secret material.
func (info *AuxInfo) UnmarshalCBOR(data []byte) error {
	if info == nil {
		return ErrNil.WithMessage("auxiliary information")
	}
	dto, err := serde.UnmarshalCBOR[*auxInfoDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal auxiliary information from CBOR")
	}
	if dto == nil {
		return ErrNil.WithMessage("auxiliary information DTO")
	}
	decoded, err := NewAuxInfo(
		dto.PaillierSecretKey,
		dto.PaillierPublicKeys,
		dto.RingPedersenSecretKey,
		dto.RingPedersenPublicKeys,
		dto.RefreshID,
	)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create auxiliary information from CBOR")
	}
	*info = *decoded
	return nil
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

// PaillierPublicKey returns the Paillier public key for id.
func (info *AuxInfo) PaillierPublicKey(id sharing.ID) (*paillier.PublicKey, bool) {
	if info == nil {
		return nil, false
	}
	key, ok := info.paillierPublicKeys[id]
	return key, ok
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

// RingPedersenPublicKey returns the ring-Pedersen public key for id.
func (info *AuxInfo) RingPedersenPublicKey(id sharing.ID) (*intcom.CommitmentKey, bool) {
	if info == nil {
		return nil, false
	}
	key, ok := info.ringPedersenPublicKeys[id]
	return key, ok
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
	if !bytes.Equal(info.refreshID, other.refreshID) {
		return false
	}
	if !equalPaillierPublicKeys(info.paillierPublicKeys, other.paillierPublicKeys) {
		return false
	}
	return equalRingPedersenPublicKeys(info.ringPedersenPublicKeys, other.ringPedersenPublicKeys)
}

// RefreshID returns the refresh identifier bound into signing transcripts.
func (info *AuxInfo) RefreshID() []byte {
	return info.refreshID
}

// Shard holds a CGGMP21 ECDSA key share and its auxiliary information.
type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	mpc.BaseShard[P, S]

	auxInfo *AuxInfo
}

type shardDTO[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Base    *mpc.BaseShard[P, S] `cbor:"base"`
	AuxInfo *AuxInfo             `cbor:"auxInfo"`
}

// NewShard returns a new shard.
func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](baseShard *mpc.BaseShard[P, S], info *AuxInfo) (*Shard[P, B, S], error) {
	if baseShard == nil {
		return nil, ErrNil.WithMessage("base shard")
	}
	if info == nil {
		return nil, ErrNil.WithMessage("auxiliary information")
	}
	shareholders := baseShard.MSP().Shareholders()
	if len(info.paillierPublicKeys) != shareholders.Size()-1 {
		return nil, ErrValidationFailed.WithMessage("paillier public key count does not match shareholders")
	}
	if len(info.ringPedersenPublicKeys) != shareholders.Size()-1 {
		return nil, ErrValidationFailed.WithMessage("ring pedersen public key count does not match shareholders")
	}
	for id := range shareholders.Iter() {
		if id == baseShard.Share().ID() {
			continue
		}
		if _, ok := info.paillierPublicKeys[id]; !ok {
			return nil, ErrValidationFailed.WithMessage("missing paillier public key for %d", id)
		}
		if _, ok := info.ringPedersenPublicKeys[id]; !ok {
			return nil, ErrValidationFailed.WithMessage("missing ring pedersen public key for %d", id)
		}
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

// MarshalCBOR serialises the shard, including its secret share and auxiliary
// trapdoor material.
func (sh *Shard[P, B, S]) MarshalCBOR() ([]byte, error) {
	if sh == nil {
		return nil, ErrNil.WithMessage("shard")
	}
	dto := &shardDTO[P, B, S]{
		Base:    &sh.BaseShard,
		AuxInfo: sh.auxInfo,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal shard to CBOR")
	}
	return data, nil
}

// UnmarshalCBOR deserialises the shard and revalidates the base shard/aux-info
// binding through NewShard.
func (sh *Shard[P, B, S]) UnmarshalCBOR(data []byte) error {
	if sh == nil {
		return ErrNil.WithMessage("shard")
	}
	dto, err := serde.UnmarshalCBOR[*shardDTO[P, B, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal shard from CBOR")
	}
	if dto == nil {
		return ErrNil.WithMessage("shard DTO")
	}
	decoded, err := NewShard(dto.Base, dto.AuxInfo)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create shard from CBOR")
	}
	*sh = *decoded
	return nil
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
