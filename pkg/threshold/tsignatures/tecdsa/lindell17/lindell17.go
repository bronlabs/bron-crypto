package lindell17

import (
	"encoding/json"
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/encryptions/paillier"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
)

const (
	// Threshold Lindell 2017 threshold (always 2).
	Threshold = 2
)

var _ tsignatures.Shard = (*Shard)(nil)

type Shard struct {
	SigningKeyShare         *tsignatures.SigningKeyShare
	PublicKeyShares         *tsignatures.PartialPublicKeys
	PaillierSecretKey       *paillier.SecretKey
	PaillierPublicKeys      ds.Map[types.SharingID, *paillier.PublicKey]
	PaillierEncryptedShares ds.Map[types.SharingID, *paillier.CipherText]

	_ ds.Incomparable
}

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

func PaillierPublicKeysAsSharingIDMappedToPublicKeys(protocol types.ThresholdProtocol, ppkMap ds.Map[types.IdentityKey, *paillier.PublicKey]) ds.Map[types.SharingID, *paillier.PublicKey] {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	out := hashmap.NewComparableHashMap[types.SharingID, *paillier.PublicKey]()
	for identityKey, ppk := range ppkMap.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			panic(fmt.Sprintf("identity key not found in sharing config: %s", identityKey.String()))
		}
		out.Put(sharingId, ppk)
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

func PaillierEncryptedSharesAsSharingIDMappedToCiphertexts(protocol types.ThresholdProtocol, eskMap ds.Map[types.IdentityKey, *paillier.CipherText]) ds.Map[types.SharingID, *paillier.CipherText] {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	out := hashmap.NewComparableHashMap[types.SharingID, *paillier.CipherText]()
	for identityKey, esk := range eskMap.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			panic(fmt.Sprintf("identity key not found in sharing config: %s", identityKey.String()))
		}
		out.Put(sharingId, esk)
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

type PartialSignature struct {
	C3 *paillier.CipherText

	_ ds.Incomparable
}

func (ps *PartialSignature) Validate(protocol types.ThresholdProtocol) error {
	if ps.C3 == nil {
		return errs.NewIsNil("c3")
	}
	return nil
}

type PreProcessingMaterial tsignatures.PreProcessingMaterial[*PrivatePreProcessingMaterial, *PreSignature]

type PrivatePreProcessingMaterial struct {
	K curves.Scalar

	_ ds.Incomparable
}

type PreSignature struct {
	BigR ds.Map[types.IdentityKey, curves.Point]

	_ ds.Incomparable
}

func (ppm *PreProcessingMaterial) Validate(myIdentityKey types.IdentityKey, protocol types.ThresholdSignatureProtocol) error {
	if ppm == nil {
		return errs.NewIsNil("receiver")
	}
	if ppm.PreSigners == nil {
		return errs.NewIsNil("presigners")
	}
	if ppm.PreSigners.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants: %d", ppm.PreSigners.Size())
	}
	if !ppm.PreSigners.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("presigners must be non empty subset of all participants")
	}
	if err := ppm.PrivateMaterial.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "private material")
	}
	if err := ppm.PreSignature.Validate(myIdentityKey, protocol, ppm.PreSigners); err != nil {
		return errs.WrapValidation(err, "presignature")
	}
	myContribution, exists := ppm.PreSignature.BigR.Get(myIdentityKey)
	if !exists {
		return errs.NewMissing("my contribution is missing")
	}
	if !myContribution.Equal(protocol.Curve().ScalarBaseMult(ppm.PrivateMaterial.K)) {
		return errs.NewValue("my contribution != k * G")
	}
	return nil
}

func (pppm *PrivatePreProcessingMaterial) Validate(protocol types.ThresholdSignatureProtocol) error {
	if pppm == nil {
		return errs.NewIsNil("receiver")
	}
	if pppm.K == nil {
		return errs.NewIsNil("K")
	}
	if !curveutils.AllScalarsOfSameCurve(protocol.Curve(), pppm.K) {
		return errs.NewCurve("K")
	}
	return nil
}

func (ps *PreSignature) Validate(myIdentityKey types.IdentityKey, protocol types.ThresholdSignatureProtocol, preSigners ds.Set[types.IdentityKey]) error {
	if ps == nil {
		return errs.NewIsNil("receiver")
	}
	if ps.BigR == nil {
		return errs.NewIsNil("BigR")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), ps.BigR.Values()...) {
		return errs.NewCurve("BigR")
	}
	if !ps.BigR.ContainsKey(myIdentityKey) {
		return errs.NewMembership("BigR does not contain my contribution")
	}
	bigRKeys := hashset.NewHashableHashSet(ps.BigR.Keys()...)
	if !bigRKeys.Equal(preSigners) {
		return errs.NewMembership("set of people with BigR is not the same as presigners")
	}
	bigRValues := hashset.NewHashableHashSet(ps.BigR.Values()...)
	if bigRValues.Size() != len(ps.BigR.Values()) {
		return errs.NewMembership("not all big R values are unique")
	}
	return nil
}

func (s *Shard) Validate(protocol types.ThresholdSignatureProtocol, holderIdentityKey types.IdentityKey, recomputeCached bool) error {
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
