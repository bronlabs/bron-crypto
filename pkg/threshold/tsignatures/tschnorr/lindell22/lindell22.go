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
