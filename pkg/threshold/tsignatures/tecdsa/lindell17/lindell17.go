package lindell17

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
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
	PaillierPublicKeys      ds.Map[types.IdentityKey, *paillier.PublicKey]
	PaillierEncryptedShares ds.Map[types.IdentityKey, *paillier.CipherText]

	_ ds.Incomparable
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
	if ppm.PreSigners.Size() < safecast.ToInt(protocol.Threshold()) {
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
	paillierPublicKeyHolders := hashset.NewHashableHashSet(s.PaillierPublicKeys.Keys()...)
	if !paillierPublicKeyHolders.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("paillier public keys holders must be subset of all participants")
	}
	if diff := protocol.Participants().Difference(paillierPublicKeyHolders); diff.Size() != 1 || !diff.Contains(holderIdentityKey) {
		return errs.NewMembership("paillier public keys holders should contain all participants except myself")
	}
	if s.PaillierEncryptedShares == nil {
		return errs.NewIsNil("paillier encrypted share")
	}
	paillierEncryptedShareHolders := hashset.NewHashableHashSet(s.PaillierEncryptedShares.Keys()...)
	if !paillierEncryptedShareHolders.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("paillier encrypted share holders must be subset of all participants")
	}
	if diff := protocol.Participants().Difference(paillierEncryptedShareHolders); diff.Size() != 1 || !diff.Contains(holderIdentityKey) {
		return errs.NewMembership("paillier encrypted share holders should contain all participants except myself")
	}
	if !paillierEncryptedShareHolders.Equal(paillierPublicKeyHolders) {
		return errs.NewMembership("number of paillier public keys != number of encrypted paillier ciphertexts")
	}
	for id, esk := range s.PaillierEncryptedShares.Iter() {
		pk, exists := s.PaillierPublicKeys.Get(id)
		if !exists {
			return errs.NewMissing("paillier public key for %s", id.String())
		}
		if err := pk.Validate(); err != nil {
			return errs.WrapValidation(err, "invalid public key %s", id.String())
		}
		if err := esk.Validate(pk); err != nil {
			return errs.WrapValidation(err, "invalid public key %s", id.String())
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

func (s *Shard) PartialPublicKeys() ds.Map[types.IdentityKey, curves.Point] {
	return s.PublicKeyShares.Shares
}

func (s *Shard) FeldmanCommitmentVector() []curves.Point {
	return s.PublicKeyShares.FeldmanCommitmentVector
}
