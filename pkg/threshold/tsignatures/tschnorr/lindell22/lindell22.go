package lindell22

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
)

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

func (s *Shard) Equal(other tsignatures.Shard) bool {
	otherShard, ok := other.(*Shard)
	return ok && s.SigningKeyShare.Equal(otherShard.SigningKeyShare) && s.PublicKeyShares.Equal(otherShard.PublicKeyShares)
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

func (s *Shard) PartialPublicKeys() ds.Map[types.SharingID, curves.Point] {
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
	if err := ppm.PreSignature.Validate(myIdentityKey, protocol, ppm.PreSigners); err != nil {
		return errs.WrapValidation(err, "presignature")
	}
	if ppm.PreSigners.Size() > 0 && !curveutils.AllIdentityKeysWithSameCurve(ppm.PreSigners.List()[0].PublicKey().Curve(), ppm.PreSigners.List()...) {
		return errs.NewCurve("not all preSigners are on the same curve")
	}
	return nil
}

type PrivatePreProcessingMaterial struct {
	K1 curves.Scalar
	K2 curves.Scalar

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

func (ps *PreSignature) Validate(myIdentityKey types.IdentityKey, protocol types.ThresholdSignatureProtocol, preSigners ds.Set[types.IdentityKey]) error {
	if ps == nil {
		return errs.NewIsNil("receiver")
	}
	if ps.BigR1 == nil {
		return errs.NewIsNil("BigR")
	}
	bigRHolders := hashset.NewHashableHashSet(ps.BigR1.Keys()...)
	if !bigRHolders.IsSubSet(preSigners) {
		return errs.NewMembership("BigR holders are not a subset of preSigners")
	}
	if diff := preSigners.Difference(bigRHolders); diff.Size() != 1 || !diff.Contains(myIdentityKey) {
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
