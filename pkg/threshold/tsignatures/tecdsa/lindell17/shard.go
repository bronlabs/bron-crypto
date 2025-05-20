package lindell17

import (
	"bytes"
	"encoding/json"

	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/indcpa/paillier"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
)

var (
	_ tsignatures.Shard = (*Shard)(nil)
	_ tsignatures.Shard = (*ExtendedShard)(nil)
)

func (s *Shard) Equal(other tsignatures.Shard) bool {
	otherShard, ok := other.(*Shard)
	if !(ok &&
		s.SigningKeyShare.Equal(otherShard.SigningKeyShare) &&
		s.PublicKeyShares.Equal(otherShard.PublicKeyShares) &&
		s.PaillierSecretKey.Equal(otherShard.PaillierSecretKey)) {

		return false
	}
	for sharingId, pk := range s.PaillierPublicKeys.Iter() {
		otherPk, exists := otherShard.PaillierPublicKeys.Get(sharingId)
		if !exists || !pk.Equal(otherPk) {
			return false
		}
	}
	for sharingId, esk := range s.PaillierEncryptedShares.Iter() {
		otherEsk, exists := otherShard.PaillierEncryptedShares.Get(sharingId)
		if !exists || !esk.Equal(otherEsk) {
			return false
		}
	}
	return true
}

func (s *Shard) Validate(protocol types.ThresholdProtocol, holderIdentityKey types.IdentityKey, recomputeCached bool) error {
	if s == nil {
		return errs.NewIsNil("receiver")
	}
	if err := s.SigningKeyShare.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid public key shares")
	}
	if err := s.PaillierSecretKey.Validate(); err != nil {
		return errs.WrapValidation(err, "paillier secret key")
	}
	if s.PaillierPublicKeys == nil {
		return errs.NewIsNil("paillier public keys")
	}
	paillierPublicKeyHolders := hashset.NewHashableHashSet(s.PaillierPublicKeysIdentityBased(protocol).Keys()...)
	if !paillierPublicKeyHolders.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("paillier public keys holders must be subset of all participants")
	}
	if diff := protocol.Participants().Difference(paillierPublicKeyHolders); diff.Size() != 1 || !diff.Contains(holderIdentityKey) {
		return errs.NewMembership("paillier public keys holders should contain all participants except myself")
	}
	if s.PaillierEncryptedShares == nil {
		return errs.NewIsNil("paillier encrypted share")
	}
	paillierEncryptedShareHolders := hashset.NewHashableHashSet(s.PaillierEncryptedSharesIdentityBased(protocol).Keys()...)
	if !paillierEncryptedShareHolders.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("paillier encrypted share holders must be subset of all participants")
	}
	if diff := protocol.Participants().Difference(paillierEncryptedShareHolders); diff.Size() != 1 || !diff.Contains(holderIdentityKey) {
		return errs.NewMembership("paillier encrypted share holders should contain all participants except myself")
	}
	if !paillierEncryptedShareHolders.Equal(paillierPublicKeyHolders) {
		return errs.NewMembership("number of paillier public keys != number of encrypted paillier ciphertexts")
	}
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	for sharingId, esk := range s.PaillierEncryptedShares.Iter() {
		identityKey, exists := sharingConfig.Get(sharingId)
		if !exists {
			return errs.NewMissing("identity key for sharing id %d", sharingId)
		}
		pk, exists := s.PaillierPublicKeys.Get(sharingId)
		if !exists {
			return errs.NewMissing("paillier public key for %s", identityKey.String())
		}
		if err := pk.Validate(); err != nil {
			return errs.WrapValidation(err, "invalid public key %s", identityKey.String())
		}
		if err := esk.Validate(pk); err != nil {
			return errs.WrapValidation(err, "invalid public key %s", identityKey.String())
		}
	}
	return nil
}
func (s *Shard) SecretShare() curves.Scalar {
	return s.SigningKeyShare.Share
}

func (s *Shard) PublicKey() curves.Point {
	return s.SigningKeyShare.PublicKey
}

func (s *Shard) PartialPublicKeys() ds.Map[types.SharingID, curves.Point] {
	return s.PublicKeyShares.Shares
}

func (s *Shard) FeldmanCommitmentVector() []curves.Point {
	return s.PublicKeyShares.FeldmanCommitmentVector
}

func (s *Shard) PaillierPublicKeysIdentityBased(protocol types.ThresholdProtocol) ds.Map[types.IdentityKey, *paillier.PublicKey] {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	out := hashmap.NewHashableHashMap[types.IdentityKey, *paillier.PublicKey]()
	for sharingId, ppk := range s.PaillierPublicKeys.Iter() {
		identityKey, exists := sharingConfig.Get(sharingId)
		if !exists {
			panic("sharing id not found in sharing config")
		}
		out.Put(identityKey, ppk)
	}
	return out
}

func (s *Shard) PaillierEncryptedSharesIdentityBased(protocol types.ThresholdProtocol) ds.Map[types.IdentityKey, *paillier.CipherText] {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	out := hashmap.NewHashableHashMap[types.IdentityKey, *paillier.CipherText]()
	for sharingId, esk := range s.PaillierEncryptedShares.Iter() {
		identityKey, exists := sharingConfig.Get(sharingId)
		if !exists {
			panic("sharing id not found in sharing config")
		}
		out.Put(identityKey, esk)
	}
	return out
}

func (s *Shard) UnmarshalJSON(data []byte) error {
	var temp struct {
		SigningKeyShare         *tsignatures.SigningKeyShare
		PublicKeyShares         *tsignatures.PartialPublicKeys
		PaillierSecretKey       *paillier.SecretKey
		PaillierPublicKeys      *hashmap.ComparableHashMap[types.SharingID, *paillier.PublicKey]
		PaillierEncryptedShares *hashmap.ComparableHashMap[types.SharingID, *paillier.CipherText]
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal shard")
	}
	s.SigningKeyShare = temp.SigningKeyShare
	s.PublicKeyShares = temp.PublicKeyShares
	s.PaillierSecretKey = temp.PaillierSecretKey
	s.PaillierPublicKeys = temp.PaillierPublicKeys
	s.PaillierEncryptedShares = temp.PaillierEncryptedShares
	return nil
}

func (s *Shard) DeriveWithChainCode(chainCode []byte, i uint32) (*ExtendedShard, error) {
	shift, childChainCode, err := tsignatures.ChildKeyDerivation(s.PublicKey(), chainCode, i)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive")
	}

	childSigningKeyShare := s.SigningKeyShare.Shift(shift)
	childPublicKeyShares := s.PublicKeyShares.Shift(shift)
	if childPublicKeyShares.PublicKey.IsAdditiveIdentity() {
		return nil, errs.NewIsIdentity("cannot derive child")
	}

	childPaillierEncryptedShares := hashmap.NewComparableHashMap[types.SharingID, *paillier.CipherText]()
	for sharingId, encryptedShare := range s.PaillierEncryptedShares.Iter() {
		pk, exists := s.PaillierPublicKeys.Get(sharingId)
		if !exists {
			return nil, errs.NewMissing("paillier public key for %d", sharingId)
		}
		childPaillierEncryptedShare, err := pk.CipherTextAddPlainText(encryptedShare, new(saferith.Int).SetBytes(shift.Bytes()))
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot derive")
		}
		childPaillierEncryptedShares.Put(sharingId, childPaillierEncryptedShare)
	}

	return &ExtendedShard{
		Shard: &Shard{
			SigningKeyShare:         childSigningKeyShare,
			PublicKeyShares:         childPublicKeyShares,
			PaillierSecretKey:       s.PaillierSecretKey,
			PaillierPublicKeys:      s.PaillierPublicKeys,
			PaillierEncryptedShares: childPaillierEncryptedShares,
		},
		ChainCodeBytes: childChainCode,
	}, nil
}

func (s *Shard) ChainCode() []byte {
	feldmanVectorBytes := sliceutils.Map(s.FeldmanCommitmentVector(), curves.Point.ToAffineCompressed)
	chainCode, _ := hashing.HmacPrefixedLength([]byte("ChainCode"), sha3.New256, feldmanVectorBytes...)
	return chainCode
}

func (s *Shard) Derive(i uint32) (*ExtendedShard, error) {
	return s.DeriveWithChainCode(s.ChainCode(), i)
}

type ExtendedShard struct {
	Shard          *Shard
	ChainCodeBytes []byte
}

func (s *ExtendedShard) ChainCode() []byte {
	return s.ChainCodeBytes
}

func (s *ExtendedShard) Equal(rhs tsignatures.Shard) bool {
	other, ok := rhs.(*ExtendedShard)
	if !ok {
		return false
	}

	return s.Shard.Equal(other.Shard) && bytes.Equal(s.ChainCodeBytes, other.ChainCodeBytes)
}

func (s *ExtendedShard) SecretShare() curves.Scalar {
	return s.Shard.SecretShare()
}

func (s *ExtendedShard) PublicKey() curves.Point {
	return s.Shard.PublicKey()
}

func (s *ExtendedShard) PartialPublicKeys() ds.Map[types.SharingID, curves.Point] {
	return s.Shard.PartialPublicKeys()
}

func (s *ExtendedShard) FeldmanCommitmentVector() []curves.Point {
	return s.Shard.FeldmanCommitmentVector()
}

func (s *ExtendedShard) AsShard() *Shard {
	return s.Shard
}

func (s *ExtendedShard) Derive(i uint32) (*ExtendedShard, error) {
	derivedShard, err := s.Shard.DeriveWithChainCode(s.ChainCodeBytes, i)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive")
	}

	return derivedShard, nil
}
