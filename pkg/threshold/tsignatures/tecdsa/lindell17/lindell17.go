package lindell17

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/indcpa/paillier"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
)

const (
	// Threshold Lindell 2017 threshold (always 2).
	Threshold = 2
)

type Shard struct {
	SigningKeyShare         *tsignatures.SigningKeyShare
	PublicKeyShares         *tsignatures.PartialPublicKeys
	PaillierSecretKey       *paillier.SecretKey
	PaillierPublicKeys      ds.Map[types.SharingID, *paillier.PublicKey]
	PaillierEncryptedShares ds.Map[types.SharingID, *paillier.CipherText]

	_ ds.Incomparable
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
