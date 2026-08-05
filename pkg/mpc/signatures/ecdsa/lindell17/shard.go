package lindell17

import (
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// AuxiliaryInfo holds the local Paillier secret key and, for each qualified
// two-party peer, the peer's public key and encrypted MSP share components. The
// secret key is trapdoor material and must be kept secret.
type AuxiliaryInfo struct {
	paillierSecretKey  *paillier.SecretKey
	paillierPublicKeys ds.Map[sharing.ID, *paillier.PublicKey]
	encryptedShares    ds.Map[sharing.ID, []*paillier.Ciphertext]
}

type auxiliaryInfoDTO struct {
	PaillierSecretKey  *paillier.SecretKey                   `cbor:"paillierSecretKey"`
	PaillierPublicKeys map[sharing.ID]*paillier.PublicKey    `cbor:"paillierPublicKeys"`
	EncryptedShares    map[sharing.ID][]*paillier.Ciphertext `cbor:"encryptedShares"`
}

// PaillierSecretKey returns the local Paillier secret key. It is trapdoor
// material and must be kept secret.
func (a *AuxiliaryInfo) PaillierSecretKey() *paillier.SecretKey {
	if a == nil {
		return nil
	}
	return a.paillierSecretKey
}

// PaillierPublicKeys returns the qualified peers' Paillier public keys.
func (a *AuxiliaryInfo) PaillierPublicKeys() ds.Map[sharing.ID, *paillier.PublicKey] {
	if a == nil {
		return nil
	}
	return a.paillierPublicKeys
}

// EncryptedShares returns copies of the qualified peers' encrypted MSP
// share-component vectors, keyed by shareholder ID.
func (a *AuxiliaryInfo) EncryptedShares() ds.Map[sharing.ID, []*paillier.Ciphertext] {
	if a == nil {
		return nil
	}
	out := hashmap.NewComparable[sharing.ID, []*paillier.Ciphertext]()
	for id, ciphertexts := range a.encryptedShares.Iter() {
		out.Put(id, slices.Clone(ciphertexts))
	}
	return out.Freeze()
}

// Equal reports whether two AuxiliaryInfo values are identical.
func (a *AuxiliaryInfo) Equal(other *AuxiliaryInfo) bool {
	if a == nil || other == nil {
		return a == other
	}
	if !a.paillierSecretKey.Equal(other.paillierSecretKey) {
		return false
	}
	if a.paillierPublicKeys.Size() != other.paillierPublicKeys.Size() ||
		a.encryptedShares.Size() != other.encryptedShares.Size() {

		return false
	}

	for id, publicKey := range a.paillierPublicKeys.Iter() {
		otherPublicKey, ok := other.paillierPublicKeys.Get(id)
		if !ok || !publicKey.Equal(otherPublicKey) {
			return false
		}
	}
	for id, ciphertexts := range a.encryptedShares.Iter() {
		otherCiphertexts, ok := other.encryptedShares.Get(id)
		if !ok || len(ciphertexts) != len(otherCiphertexts) {
			return false
		}
		for i, ciphertext := range ciphertexts {
			if !ciphertext.Equal(otherCiphertexts[i]) {
				return false
			}
		}
	}

	return true
}

// MarshalCBOR serialises the auxiliary information, including the local
// Paillier trapdoor material.
func (a *AuxiliaryInfo) MarshalCBOR() ([]byte, error) {
	if a == nil {
		return nil, ErrInvalidArgument.WithMessage("auxiliary information is nil")
	}
	paillierPublicKeys := make(map[sharing.ID]*paillier.PublicKey, a.paillierPublicKeys.Size())
	for id, publicKey := range a.paillierPublicKeys.Iter() {
		paillierPublicKeys[id] = publicKey
	}
	encryptedShares := make(map[sharing.ID][]*paillier.Ciphertext, a.encryptedShares.Size())
	for id, ciphertexts := range a.encryptedShares.Iter() {
		encryptedShares[id] = slices.Clone(ciphertexts)
	}
	dto := &auxiliaryInfoDTO{
		PaillierSecretKey:  a.paillierSecretKey,
		PaillierPublicKeys: paillierPublicKeys,
		EncryptedShares:    encryptedShares,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Lindell17 auxiliary information")
	}
	return data, nil
}

// UnmarshalCBOR deserialises and validates the auxiliary information. The
// decoded Paillier secret key is trapdoor material and must be kept secret.
func (a *AuxiliaryInfo) UnmarshalCBOR(data []byte) error {
	if a == nil {
		return ErrInvalidArgument.WithMessage("auxiliary information is nil")
	}
	dto, err := serde.UnmarshalCBOR[*auxiliaryInfoDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Lindell17 auxiliary information")
	}
	if dto == nil {
		return ErrInvalidArgument.WithMessage("auxiliary information DTO is nil")
	}
	if dto.PaillierPublicKeys == nil || dto.EncryptedShares == nil {
		return ErrInvalidArgument.WithMessage("auxiliary information maps are nil")
	}
	auxInfo, err := NewAuxiliaryInfo(
		dto.PaillierSecretKey,
		hashmap.NewImmutableComparableFromNativeLike(dto.PaillierPublicKeys),
		hashmap.NewImmutableComparableFromNativeLike(dto.EncryptedShares),
	)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create AuxiliaryInfo from deserialised data")
	}
	*a = *auxInfo
	return nil
}

// NewAuxiliaryInfo constructs and validates Lindell17 auxiliary information.
func NewAuxiliaryInfo(
	paillierSecretKey *paillier.SecretKey,
	paillierPublicKeys ds.Map[sharing.ID, *paillier.PublicKey],
	encryptedShares ds.Map[sharing.ID, []*paillier.Ciphertext],
) (*AuxiliaryInfo, error) {
	if paillierSecretKey == nil {
		return nil, ErrInvalidArgument.WithMessage("paillier secret key is nil")
	}
	if paillierSecretKey.Group() == nil {
		return nil, ErrInvalidArgument.WithMessage("paillier secret key is invalid")
	}
	if paillierPublicKeys == nil {
		return nil, ErrInvalidArgument.WithMessage("paillier public keys map is nil")
	}
	if encryptedShares == nil {
		return nil, ErrInvalidArgument.WithMessage("encrypted shares map is nil")
	}
	publicKeyIDs := paillierPublicKeys.Keys()
	encryptedShareIDs := encryptedShares.Keys()
	slices.Sort(publicKeyIDs)
	slices.Sort(encryptedShareIDs)
	if !slices.Equal(publicKeyIDs, encryptedShareIDs) {
		return nil, ErrInvalidArgument.WithMessage("paillier public keys and encrypted shares maps must have the same keys")
	}

	publicKeys := hashmap.NewComparable[sharing.ID, *paillier.PublicKey]()
	ciphertextMap := hashmap.NewComparable[sharing.ID, []*paillier.Ciphertext]()
	for id, publicKey := range paillierPublicKeys.Iter() {
		if publicKey == nil || publicKey.Group() == nil {
			return nil, ErrInvalidArgument.WithMessage("paillier public key for shareholder %d is nil or invalid", id)
		}
		ciphertexts, _ := encryptedShares.Get(id)
		if len(ciphertexts) == 0 {
			return nil, ErrInvalidArgument.WithMessage("encrypted share for shareholder %d is nil or empty", id)
		}
		for i, ciphertext := range ciphertexts {
			if ciphertext == nil {
				return nil, ErrInvalidArgument.WithMessage("encrypted share component %d for shareholder %d is nil", i, id)
			}
			if ciphertext.Value() == nil || !publicKey.CiphertextGroup().Contains(ciphertext.Value()) {
				return nil, ErrInvalidArgument.WithMessage("encrypted share component %d for shareholder %d uses the wrong paillier key", i, id)
			}
		}
		publicKeys.Put(id, publicKey)
		ciphertextMap.Put(id, slices.Clone(ciphertexts))
	}

	return &AuxiliaryInfo{
		paillierSecretKey:  paillierSecretKey,
		paillierPublicKeys: publicKeys.Freeze(),
		encryptedShares:    ciphertextMap.Freeze(),
	}, nil
}

// Shard holds an MSP-based ECDSA share and Lindell17 auxiliary information. The
// MSP share and Paillier secret key are secret material.
type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	mpc.BaseShard[P, S]
	AuxiliaryInfo
}

// NewShard constructs a Lindell17 shard and validates that every peer in a
// qualified two-party quorum has one encrypted ciphertext per raw share
// component.
func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	baseShard *mpc.BaseShard[P, S],
	auxInfo *AuxiliaryInfo,
) (*Shard[P, B, S], error) {
	if baseShard == nil {
		return nil, ErrInvalidArgument.WithMessage("base shard is nil")
	}
	if auxInfo == nil {
		return nil, ErrInvalidArgument.WithMessage("auxiliary information is nil")
	}
	if baseShard.Share() == nil || baseShard.MSP() == nil || baseShard.VerificationVector() == nil {
		return nil, ErrInvalidArgument.WithMessage("base shard is invalid")
	}
	validatedBaseShard, err := mpc.NewBaseShard(
		baseShard.Share(),
		baseShard.VerificationVector(),
		baseShard.MSP(),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("base shard is invalid")
	}
	validatedAuxInfo, err := NewAuxiliaryInfo(
		auxInfo.paillierSecretKey,
		auxInfo.paillierPublicKeys,
		auxInfo.encryptedShares,
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("auxiliary information is invalid")
	}
	baseShard = validatedBaseShard
	auxInfo = validatedAuxInfo

	shareholders := baseShard.MSP().Shareholders()
	selfID := baseShard.Share().ID()
	expectedPeers := make([]sharing.ID, 0, shareholders.Size()-1)
	for id := range shareholders.Iter() {
		if id == selfID || !baseShard.MSP().Accepts(selfID, id) {
			continue
		}
		expectedPeers = append(expectedPeers, id)
	}
	slices.Sort(expectedPeers)
	publicKeyIDs := auxInfo.paillierPublicKeys.Keys()
	encryptedShareIDs := auxInfo.encryptedShares.Keys()
	slices.Sort(publicKeyIDs)
	slices.Sort(encryptedShareIDs)
	if !slices.Equal(publicKeyIDs, expectedPeers) {
		return nil, ErrInvalidArgument.WithMessage("paillier public key keys do not match qualified peers")
	}
	if !slices.Equal(encryptedShareIDs, expectedPeers) {
		return nil, ErrInvalidArgument.WithMessage("encrypted share keys do not match qualified peers")
	}

	for _, id := range expectedPeers {
		publicKey, _ := auxInfo.paillierPublicKeys.Get(id)
		ciphertexts, _ := auxInfo.encryptedShares.Get(id)
		publicShare, ok := baseShard.PublicKeyShares().Get(id)
		if !ok || publicShare == nil || len(publicShare.Value()) == 0 {
			return nil, ErrInvalidArgument.WithMessage("missing lifted MSP share for shareholder %d", id)
		}
		if len(ciphertexts) != len(publicShare.Value()) {
			return nil, ErrInvalidArgument.WithMessage("encrypted share component count for shareholder %d does not match MSP share", id)
		}
		if publicKey == nil {
			return nil, ErrInvalidArgument.WithMessage("invalid encrypted share for shareholder %d", id)
		}
		for _, ciphertext := range ciphertexts {
			if ciphertext == nil || !ciphertext.Group().Equal(publicKey.CiphertextGroup()) {
				return nil, ErrInvalidArgument.WithMessage("invalid encrypted share for shareholder %d", id)
			}
		}
	}

	return &Shard[P, B, S]{
		BaseShard:     *baseShard,
		AuxiliaryInfo: *auxInfo,
	}, nil
}

// PublicKey returns the aggregate ECDSA public key.
func (s *Shard[P, B, S]) PublicKey() *sigecdsa.PublicKey[P, B, S] {
	publicKey, err := sigecdsa.NewPublicKey(s.PublicKeyValue())
	if err != nil {
		panic(err) // The validated base shard always contains a valid public key.
	}
	return publicKey
}

// Equal reports whether two shards are identical.
func (s *Shard[P, B, S]) Equal(other *Shard[P, B, S]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.BaseShard.Equal(&other.BaseShard) && s.AuxiliaryInfo.Equal(&other.AuxiliaryInfo)
}

type shardDTO[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Base *mpc.BaseShard[P, S] `cbor:"base"`
	Aux  *AuxiliaryInfo       `cbor:"auxiliaryInfo"`
}

// MarshalCBOR serialises the shard, including its secret share and Paillier
// trapdoor material.
func (s *Shard[P, B, S]) MarshalCBOR() ([]byte, error) {
	if s == nil {
		return nil, ErrInvalidArgument.WithMessage("shard is nil")
	}
	dto := &shardDTO[P, B, S]{
		Base: &s.BaseShard,
		Aux:  &s.AuxiliaryInfo,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Lindell17 shard")
	}
	return data, nil
}

// UnmarshalCBOR deserialises a shard and revalidates the base-shard and
// auxiliary-information binding.
func (s *Shard[P, B, S]) UnmarshalCBOR(data []byte) error {
	if s == nil {
		return ErrInvalidArgument.WithMessage("shard is nil")
	}
	dto, err := serde.UnmarshalCBOR[*shardDTO[P, B, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Lindell17 shard")
	}
	if dto == nil {
		return ErrInvalidArgument.WithMessage("shard DTO is nil")
	}
	shard, err := NewShard(
		dto.Base,
		dto.Aux,
	)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create Shard from deserialised data")
	}
	*s = *shard
	return nil
}
