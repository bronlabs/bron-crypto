package lindell22

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

type PartialSignature struct {
	E curves.Scalar
	R curves.Point
	S curves.Scalar

	_ ds.Incomparable
}

var _ tsignatures.Shard = (*Shard)(nil)

type Shard struct {
	SigningKeyShare *tsignatures.SigningKeyShare
	PublicKeyShares *tsignatures.PartialPublicKeys

	_ ds.Incomparable
}

func NewShard(protocol types.ThresholdProtocol, signingKeyShare *tsignatures.SigningKeyShare, partialPublicKeys *tsignatures.PartialPublicKeys) (*Shard, error) {
	if err := signingKeyShare.Validate(protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid signing key share")
	}
	if err := partialPublicKeys.Validate(protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid public key share")
	}

	shard := &Shard{
		SigningKeyShare: signingKeyShare,
		PublicKeyShares: partialPublicKeys,
	}

	return shard, nil
}

func (s *Shard) Validate(protocol types.ThresholdProtocol) error {
	if err := s.SigningKeyShare.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid public key shares map")
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

type PreProcessingMaterial tsignatures.PreProcessingMaterial[*PrivatePreProcessingMaterial, *PreSignature]

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
	if ppm.PrivateMaterial == nil {
		return errs.NewIsNil("private material")
	}
	if err := ppm.PrivateMaterial.Validate(ppm.PreSigners); err != nil {
		return errs.WrapValidation(err, "private material")
	}
	if ppm.PreSignature == nil {
		return errs.NewIsNil("public material")
	}
	if err := ppm.PreSignature.Validate(protocol, ppm.PreSigners); err != nil {
		return errs.WrapValidation(err, "presignature")
	}
	if !hashset.NewHashableHashSet(ppm.PreSignature.BigR1.Keys()...).Equal(hashset.NewHashableHashSet(ppm.PrivateMaterial.Seeds.Keys()...)) {
		return errs.NewMembership("seed holders and presignature contributors are not the same set")
	}
	if ppm.PreSigners.Size() > 0 && !curveutils.AllIdentityKeysWithSameCurve(ppm.PreSigners.List()[0].PublicKey().Curve(), ppm.PreSigners.List()...) {
		return errs.NewCurve("not all preSigners are on the same curve")
	}
	return nil
}

type PrivatePreProcessingMaterial struct {
	K1    curves.Scalar
	K2    curves.Scalar
	Seeds przs.PairWiseSeeds

	_ ds.Incomparable
}

func (pppm *PrivatePreProcessingMaterial) Validate(preSigners ds.Set[types.IdentityKey]) error {
	if pppm == nil {
		return errs.NewIsNil("receiver")
	}
	if pppm.K1 == nil {
		return errs.NewIsNil("k")
	}
	if pppm.K2 == nil {
		return errs.NewIsNil("k2")
	}
	if pppm.Seeds == nil {
		return errs.NewIsNil("seeds")
	}
	seeders := hashset.NewHashableHashSet(pppm.Seeds.Keys()...)
	if !seeders.IsSubSet(preSigners) {
		return errs.NewMembership("we have seeds from people who are not a participant in this protocol")
	}
	if seeders.SymmetricDifference(preSigners).Size() != 1 {
		return errs.NewMembership("seed holders should contain all presigners except myself")
	}
	for pair := range pppm.Seeds.Iter() {
		if ct.IsAllZero(pair.Value[:]) == 1 {
			return errs.NewIsZero("found seed that's all zero")
		}
	}
	if !curveutils.AllIdentityKeysWithSameCurve(preSigners.List()[0].PublicKey().Curve(), preSigners.List()...) {
		return errs.NewCurve("not all preSigners are on the same curve")
	}
	return nil
}

type PreSignature struct {
	BigR1 ds.Map[types.IdentityKey, curves.Point]
	BigR2 ds.Map[types.IdentityKey, curves.Point]

	_ ds.Incomparable
}

func (ps *PreSignature) Validate(protocol types.ThresholdSignatureProtocol, preSigners ds.Set[types.IdentityKey]) error {
	if ps == nil {
		return errs.NewIsNil("receiver")
	}
	if ps.BigR1 == nil {
		return errs.NewIsNil("BigR")
	}
	bigRHolders := hashset.NewHashableHashSet(ps.BigR1.Keys()...)
	if !bigRHolders.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("BigR holders are not a subset of total participants")
	}
	if bigRHolders.SymmetricDifference(preSigners).Size() != 1 {
		return errs.NewMembership("BigR holders should contain all presigners except myself")
	}
	if ps.BigR2 == nil {
		return errs.NewIsNil("BigR2")
	}
	bigR2Holders := hashset.NewHashableHashSet(ps.BigR2.Keys()...)
	if !bigR2Holders.Equal(bigRHolders) {
		return errs.NewMembership("BigR2 holders are not equal to BigR holders")
	}
	if preSigners.Size() > 0 && !curveutils.AllIdentityKeysWithSameCurve(preSigners.List()[0].PublicKey().Curve(), preSigners.List()...) {
		return errs.NewCurve("not all preSigners are on the same curve")
	}
	return nil
}
