package lindell22

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
)

//var _ tsignatures.Shard = (*Shard)(nil)

type Shard[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	SigningKeyShare *tsignatures.SigningKeyShare[C, P, F, S]
	PublicKeyShares *tsignatures.PartialPublicKeys[C, P, F, S]

	_ ds.Incomparable
}

func NewShard[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](signingKeyShare *tsignatures.SigningKeyShare[C, P, F, S], partialPublicKeys *tsignatures.PartialPublicKeys[C, P, F, S]) (*Shard[C, P, F, S], error) {
	//if err := signingKeyShare.Validate(protocol); err != nil {
	//	return nil, errs.WrapValidation(err, "invalid signing key share")
	//}
	//if err := partialPublicKeys.Validate(protocol); err != nil {
	//	return nil, errs.WrapValidation(err, "invalid public key share")
	//}

	shard := &Shard[C, P, F, S]{
		SigningKeyShare: signingKeyShare,
		PublicKeyShares: partialPublicKeys,
	}

	return shard, nil
}

func (s *Shard[C, P, F, S]) Equal(other tsignatures.Shard[P, F, S]) bool {
	otherShard, ok := other.(*Shard[C, P, F, S])
	return ok && s.SigningKeyShare.Equal(otherShard.SigningKeyShare) && s.PublicKeyShares.Equal(otherShard.PublicKeyShares)
}

func (s *Shard[C, P, F, S]) Validate(protocol types.ThresholdProtocol[C, P, F, S]) error {
	//if err := s.SigningKeyShare.Validate(protocol); err != nil {
	//	return errs.WrapValidation(err, "invalid signing key share")
	//}
	//if err := s.PublicKeyShares.Validate(protocol); err != nil {
	//	return errs.WrapValidation(err, "invalid public key shares map")
	//}
	return nil
}

func (s *Shard[C, P, F, S]) SecretShare() S {
	return s.SigningKeyShare.Share
}

func (s *Shard[C, P, F, S]) PublicKey() P {
	return s.SigningKeyShare.PublicKey
}

func (s *Shard[C, P, F, S]) PartialPublicKeys() ds.Map[types.SharingID, P] {
	return s.PublicKeyShares.Shares
}

func (s *Shard[C, P, F, S]) FeldmanCommitmentVector() []P {
	return s.PublicKeyShares.FeldmanCommitmentVector
}

//type PreProcessingMaterial tsignatures.PreProcessingMaterial[*PrivatePreProcessingMaterial, *PreSignature]
//
//func (ppm *PreProcessingMaterial) Validate(myIdentityKey types.IdentityKey, protocol types.ThresholdSignatureProtocol) error {
//	if ppm == nil {
//		return errs.NewIsNil("receiver")
//	}
//	if ppm.PreSigners == nil {
//		return errs.NewIsNil("presigners")
//	}
//	if ppm.PreSigners.Size() < int(protocol.Threshold()) {
//		return errs.NewSize("not enough session participants: %d", ppm.PreSigners.Size())
//	}
//	if !ppm.PreSigners.IsSubSet(protocol.Participants()) {
//		return errs.NewMembership("presigners must be non empty subset of all participants")
//	}
//	if ppm.PrivateMaterial == nil {
//		return errs.NewIsNil("private material")
//	}
//	if err := ppm.PrivateMaterial.Validate(ppm.PreSigners); err != nil {
//		return errs.WrapValidation(err, "private material")
//	}
//	if ppm.PreSignature == nil {
//		return errs.NewIsNil("public material")
//	}
//	if err := ppm.PreSignature.Validate(myIdentityKey, protocol, ppm.PreSigners); err != nil {
//		return errs.WrapValidation(err, "presignature")
//	}
//	if ppm.PreSigners.Size() > 0 && !curveutils.AllIdentityKeysWithSameCurve(ppm.PreSigners.List()[0].PublicKey().Curve(), ppm.PreSigners.List()...) {
//		return errs.NewCurve("not all preSigners are on the same curve")
//	}
//	return nil
//}
//
//type PrivatePreProcessingMaterial struct {
//	K1 curves.Scalar
//	K2 curves.Scalar
//
//	_ ds.Incomparable
//}
//
//func (pppm *PrivatePreProcessingMaterial) Validate(preSigners ds.Set[types.IdentityKey]) error {
//	if pppm == nil {
//		return errs.NewIsNil("receiver")
//	}
//	if pppm.K1 == nil {
//		return errs.NewIsNil("k")
//	}
//	if pppm.K2 == nil {
//		return errs.NewIsNil("k2")
//	}
//	if !curveutils.AllIdentityKeysWithSameCurve(preSigners.List()[0].PublicKey().Curve(), preSigners.List()...) {
//		return errs.NewCurve("not all preSigners are on the same curve")
//	}
//
//	return nil
//}
//
//type PreSignature struct {
//	BigR1 ds.Map[types.IdentityKey, curves.Point]
//	BigR2 ds.Map[types.IdentityKey, curves.Point]
//
//	_ ds.Incomparable
//}
//
//func (ps *PreSignature) Validate(myIdentityKey types.IdentityKey, protocol types.ThresholdSignatureProtocol, preSigners ds.Set[types.IdentityKey]) error {
//	if ps == nil {
//		return errs.NewIsNil("receiver")
//	}
//	if ps.BigR1 == nil {
//		return errs.NewIsNil("BigR")
//	}
//	bigRHolders := hashset.NewHashableHashSet(ps.BigR1.Keys()...)
//	if !bigRHolders.IsSubSet(preSigners) {
//		return errs.NewMembership("BigR holders are not a subset of preSigners")
//	}
//	if diff := preSigners.Difference(bigRHolders); diff.Size() != 1 || !diff.Contains(myIdentityKey) {
//		return errs.NewMembership("BigR holders should contain all presigners except myself")
//	}
//	if ps.BigR2 == nil {
//		return errs.NewIsNil("BigR2")
//	}
//	bigR2Holders := hashset.NewHashableHashSet(ps.BigR2.Keys()...)
//	if !bigR2Holders.Equal(bigRHolders) {
//		return errs.NewMembership("BigR2 holders are not equal to BigR holders")
//	}
//	if preSigners.Size() > 0 && !curveutils.AllIdentityKeysWithSameCurve(preSigners.List()[0].PublicKey().Curve(), preSigners.List()...) {
//		return errs.NewCurve("not all preSigners are on the same curve")
//	}
//	return nil
//}
