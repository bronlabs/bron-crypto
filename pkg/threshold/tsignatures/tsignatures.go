package tsignatures

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

type Shard interface {
	SecretShare() curves.Scalar
	PublicKey() curves.Point
	PartialPublicKeys() ds.Map[types.IdentityKey, curves.Point]
	FeldmanCommitmentVector() []curves.Point
}

type SigningKeyShare struct {
	Share     curves.Scalar
	PublicKey curves.Point

	_ ds.Incomparable
}

func (s *SigningKeyShare) Validate(protocol types.ThresholdProtocol) error {
	if s == nil {
		return errs.NewIsNil("signing key share is nil")
	}
	if s.Share.IsZero() {
		return errs.NewIsZero("share can't be zero")
	}
	if s.PublicKey.IsAdditiveIdentity() {
		return errs.NewIsIdentity("public key can't be at infinity")
	}
	if !s.PublicKey.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	if !curveutils.AllOfSameCurve(protocol.Curve(), s.Share, s.PublicKey) {
		return errs.NewCurve("curve mismatch")
	}
	return nil
}

func (s *SigningKeyShare) ToAdditive(myIdentityKey types.IdentityKey, quorum ds.Set[types.IdentityKey], protocol types.ThresholdProtocol) (curves.Scalar, error) {
	if !quorum.IsSubSet(protocol.Participants()) {
		return nil, errs.NewMembership("present participants is not a subset of total participants")
	}
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId := uint(0)
	shamirIdentities := make([]uint, quorum.Size())
	i := 0
	for identityKey := range quorum.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("could not find participant sharing id %s", identityKey.String())
		}
		if identityKey.Equal(myIdentityKey) {
			mySharingId = uint(sharingId)
		}
		shamirIdentities[i] = uint(sharingId)
		i++
	}
	if mySharingId == 0 {
		return nil, errs.NewMissing("could not find my sharing id")
	}
	shamirShare := &shamir.Share{
		Id:    mySharingId,
		Value: s.Share,
	}
	additiveShare, err := shamirShare.ToAdditive(shamirIdentities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive additive share")
	}
	return additiveShare, nil
}

type PartialPublicKeys struct {
	PublicKey               curves.Point
	Shares                  ds.Map[types.IdentityKey, curves.Point]
	FeldmanCommitmentVector []curves.Point

	_ ds.Incomparable
}

func (p *PartialPublicKeys) ToAdditive(protocol types.ThresholdSignatureProtocol, signers ds.Set[types.IdentityKey]) (ds.Map[types.IdentityKey, curves.Point], error) {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	signersSharingIds := make([]uint, signers.Size())
	for i, signer := range signers.List() {
		sharingId, exists := sharingConfig.Reverse().Get(signer)
		if !exists {
			return nil, errs.NewFailed("invalid identity")
		}
		signersSharingIds[i] = uint(sharingId)
	}

	publicShares := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	for signer := range signers.Iter() {
		publicKeyShare, exists := p.Shares.Get(signer)
		if !exists {
			return nil, errs.NewFailed("invalid identity")
		}

		mySharingId, exists := sharingConfig.Reverse().Get(signer)
		if !exists {
			return nil, errs.NewFailed("invalid identity")
		}

		lagrangeCoefficient, err := (&shamir.Share{
			Id:    uint(mySharingId),
			Value: publicKeyShare.Curve().ScalarField().One(),
		}).ToAdditive(signersSharingIds)
		if err != nil {
			return nil, errs.WrapFailed(err, "invalid identity")
		}

		partialPublicKey := publicKeyShare.ScalarMul(lagrangeCoefficient)
		publicShares.Put(signer, partialPublicKey)
	}

	return publicShares, nil
}

func (p *PartialPublicKeys) Validate(protocol types.ThresholdProtocol) error {
	if p == nil {
		return errs.NewIsNil("receiver")
	}
	if p.PublicKey == nil {
		return errs.NewIsNil("public key")
	}
	if !p.PublicKey.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	if len(p.FeldmanCommitmentVector) != safecast.ToInt(protocol.Threshold()) {
		return errs.NewLength("feldman commitment vector length is invalid")
	}
	if p.Shares == nil {
		return errs.NewIsNil("shares map")
	}
	partialPublicKeyHolders := hashset.NewHashableHashSet(p.Shares.Keys()...)
	if !partialPublicKeyHolders.Equal(protocol.Participants()) {
		return errs.NewMembership("shares map is not equal to the participant set")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), p.PublicKey) {
		return errs.NewCurve("public key")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), p.Shares.Values()...) {
		return errs.NewCurve("shares map")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), p.FeldmanCommitmentVector...) {
		return errs.NewCurve("feldman commitment vector")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	sharingIds := make([]curves.Scalar, protocol.TotalParties())
	partialPublicKeys := make([]curves.Point, protocol.TotalParties())
	for i := uint(0); i < protocol.TotalParties(); i++ {
		sharingId := types.SharingID(i + 1)
		sharingIds[i] = p.PublicKey.Curve().ScalarField().New(uint64(sharingId))
		identityKey, exists := sharingConfig.Get(sharingId)
		if !exists {
			return errs.NewMissing("missing identity key for sharing id %d", i+1)
		}
		partialPublicKey, exists := p.Shares.Get(identityKey)
		if !exists {
			return errs.NewMissing("partial public key doesn't exist for sharing id %d", sharingId)
		}
		partialPublicKeys[i] = partialPublicKey
	}
	evaluateAt := p.PublicKey.Curve().ScalarField().Zero() // because f(0) would be the private key which means interpolating in the exponent should give us the public key
	reconstructedPublicKey, err := lagrange.InterpolateInTheExponent(p.PublicKey.Curve(), sharingIds, partialPublicKeys, evaluateAt)
	if err != nil {
		return errs.WrapFailed(err, "could not interpolate partial public keys in the exponent")
	}
	if !reconstructedPublicKey.Equal(p.PublicKey) {
		return errs.NewVerification("reconstructed public key is incorrect")
	}
	return nil
}

type PreProcessingMaterial[PrivateType any, PreSignatureType any] struct {
	PreSigners      ds.Set[types.IdentityKey]
	PrivateMaterial PrivateType
	PreSignature    PreSignatureType

	_ ds.Incomparable
}
