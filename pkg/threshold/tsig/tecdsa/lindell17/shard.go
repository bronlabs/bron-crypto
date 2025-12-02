package lindell17

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
)

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

func (a *AuxiliaryInfo) PaillierPrivateKey() *paillier.PrivateKey {
	return a.paillierPrivateKey
}

func (a *AuxiliaryInfo) PaillierPublicKeys() ds.Map[sharing.ID, *paillier.PublicKey] {
	return a.paillierPublicKeys
}

func (a *AuxiliaryInfo) EncryptedShares() ds.Map[sharing.ID, *paillier.Ciphertext] {
	return a.encryptedShares
}

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
	return serde.MarshalCBOR(dto)
}

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

func NewAuxiliaryInfo(paillierPrivateKey *paillier.PrivateKey, paillierPublicKeys ds.Map[sharing.ID, *paillier.PublicKey], encryptedShares ds.Map[sharing.ID, *paillier.Ciphertext]) (*AuxiliaryInfo, error) {
	if paillierPrivateKey == nil {
		return nil, errs.NewIsNil("paillier private key is nil")
	}
	if paillierPublicKeys == nil {
		return nil, errs.NewIsNil("paillier public keys map is nil")
	}
	if encryptedShares == nil {
		return nil, errs.NewIsNil("encrypted shares map is nil")
	}
	return &AuxiliaryInfo{
		paillierPrivateKey: paillierPrivateKey,
		paillierPublicKeys: paillierPublicKeys,
		encryptedShares:    encryptedShares,
	}, nil
}

type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	*tecdsa.Shard[P, B, S]
	AuxiliaryInfo
}

func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](baseShard *tecdsa.Shard[P, B, S], auxInfo *AuxiliaryInfo) (*Shard[P, B, S], error) {
	if baseShard == nil || auxInfo == nil {
		return nil, errs.NewIsNil("cannot create Shard with nil fields")
	}
	return &Shard[P, B, S]{
		Shard:         baseShard,
		AuxiliaryInfo: *auxInfo,
	}, nil
}

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

func (s *Shard[P, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &shardDTO[P, B, S]{
		Shard: s.Shard,
		Aux:   s.AuxiliaryInfo,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal dkls23 Shard")
	}
	return data, nil
}

func (s *Shard[P, B, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shardDTO[P, B, S]](data)
	if err != nil {
		return err
	}
	s.Shard = dto.Shard
	s.AuxiliaryInfo = dto.Aux
	return nil
}
