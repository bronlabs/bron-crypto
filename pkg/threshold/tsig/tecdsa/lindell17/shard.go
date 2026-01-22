package lindell17

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// AuxiliaryInfo holds Paillier keys and encrypted shares for Lindell17.
type AuxiliaryInfo struct {
	paillierPrivateKey *paillier.PrivateKey
	paillierPublicKeys ds.Map[sharing.ID, *paillier.PublicKey]
	encryptedShares    ds.Map[sharing.ID, *paillier.Ciphertext]
}

type auxiliaryInfoDTO struct {
	PaillierPrivateKey *paillier.PrivateKey                `cbor:"paillierPrivateKey"`
	PaillierPublicKeys map[sharing.ID]*paillier.PublicKey  `cbor:"paillierPublicKeys"`
	EncryptedShares    map[sharing.ID]*paillier.Ciphertext `cbor:"encryptedShares"`
}

// PaillierPrivateKey returns the stored Paillier private key.
func (a *AuxiliaryInfo) PaillierPrivateKey() *paillier.PrivateKey {
	return a.paillierPrivateKey
}

// PaillierPublicKeys returns the map of Paillier public keys.
func (a *AuxiliaryInfo) PaillierPublicKeys() ds.Map[sharing.ID, *paillier.PublicKey] {
	return a.paillierPublicKeys
}

// EncryptedShares returns the encrypted shares map.
func (a *AuxiliaryInfo) EncryptedShares() ds.Map[sharing.ID, *paillier.Ciphertext] {
	return a.encryptedShares
}

// Equal compares two AuxiliaryInfo values.
func (a *AuxiliaryInfo) Equal(rhs *AuxiliaryInfo) bool {
	if a == nil || rhs == nil {
		return a == rhs
	}
	if !a.paillierPrivateKey.Equal(rhs.paillierPrivateKey) {
		return false
	}
	if a.paillierPublicKeys.Size() != rhs.paillierPublicKeys.Size() {
		return false
	}
	if a.encryptedShares.Size() != rhs.encryptedShares.Size() {
		return false
	}

	for id, pkl := range a.paillierPublicKeys.Iter() {
		pkr, ok := rhs.paillierPublicKeys.Get(id)
		if !ok || !pkl.Equal(pkr) {
			return false
		}
	}
	for id, skl := range a.encryptedShares.Iter() {
		skr, ok := rhs.encryptedShares.Get(id)
		if !ok || !skl.Equal(skr) {
			return false
		}
	}

	return true
}

// MarshalCBOR encodes AuxiliaryInfo in CBOR.
func (a *AuxiliaryInfo) MarshalCBOR() ([]byte, error) {
	paillierPublicKeys := make(map[sharing.ID]*paillier.PublicKey)
	for id, pk := range a.paillierPublicKeys.Iter() {
		paillierPublicKeys[id] = pk
	}
	encryptedShares := make(map[sharing.ID]*paillier.Ciphertext)
	for id, c := range a.encryptedShares.Iter() {
		encryptedShares[id] = c
	}
	dto := &auxiliaryInfoDTO{
		PaillierPrivateKey: a.paillierPrivateKey,
		PaillierPublicKeys: paillierPublicKeys,
		EncryptedShares:    encryptedShares,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal dkls23 auxiliary info")
	}
	return data, nil
}

// UnmarshalCBOR decodes AuxiliaryInfo from CBOR.
func (a *AuxiliaryInfo) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*auxiliaryInfoDTO](data)
	if err != nil {
		return err
	}
	a.paillierPrivateKey = dto.PaillierPrivateKey
	a.paillierPublicKeys = hashmap.NewImmutableComparableFromNativeLike(dto.PaillierPublicKeys)
	a.encryptedShares = hashmap.NewImmutableComparableFromNativeLike(dto.EncryptedShares)
	return nil
}

// NewAuxiliaryInfo constructs an AuxiliaryInfo instance.
func NewAuxiliaryInfo(paillierPrivateKey *paillier.PrivateKey, paillierPublicKeys ds.Map[sharing.ID, *paillier.PublicKey], encryptedShares ds.Map[sharing.ID, *paillier.Ciphertext]) (*AuxiliaryInfo, error) {
	if paillierPrivateKey == nil {
		return nil, ErrInvalidArgument.WithMessage("paillier private key is nil")
	}
	if paillierPublicKeys == nil {
		return nil, ErrInvalidArgument.WithMessage("paillier public keys map is nil")
	}
	if encryptedShares == nil {
		return nil, ErrInvalidArgument.WithMessage("encrypted shares map is nil")
	}
	return &AuxiliaryInfo{
		paillierPrivateKey: paillierPrivateKey,
		paillierPublicKeys: paillierPublicKeys,
		encryptedShares:    encryptedShares,
	}, nil
}

// Shard wraps a base tECDSA shard with Lindell17 auxiliary info.
type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	*tecdsa.Shard[P, B, S]
	AuxiliaryInfo
}

// NewShard constructs a Lindell17 shard from a base shard and auxiliary info.
func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](baseShard *tecdsa.Shard[P, B, S], auxInfo *AuxiliaryInfo) (*Shard[P, B, S], error) {
	if baseShard == nil || auxInfo == nil {
		return nil, ErrInvalidArgument.WithMessage("cannot create Shard with nil fields")
	}
	return &Shard[P, B, S]{
		Shard:         baseShard,
		AuxiliaryInfo: *auxInfo,
	}, nil
}

// Equal compares two shards for equality.
func (s *Shard[P, B, S]) Equal(rhs *Shard[P, B, S]) bool {
	if s == nil || rhs == nil {
		return s == rhs
	}
	return s.Shard.Equal(rhs.Shard) && s.AuxiliaryInfo.Equal(&rhs.AuxiliaryInfo)
}

type shardDTO[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Shard *tecdsa.Shard[P, B, S] `cbor:"shard"`
	Aux   AuxiliaryInfo          `cbor:"auxiliaryInfo"`
}

// MarshalCBOR encodes the shard in CBOR.
func (s *Shard[P, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &shardDTO[P, B, S]{
		Shard: s.Shard,
		Aux:   s.AuxiliaryInfo,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal dkls23 Shard")
	}
	return data, nil
}

// UnmarshalCBOR decodes the shard from CBOR.
func (s *Shard[P, B, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shardDTO[P, B, S]](data)
	if err != nil {
		return err
	}
	s.Shard = dto.Shard
	s.AuxiliaryInfo = dto.Aux
	return nil
}
