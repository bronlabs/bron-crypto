package boldyreva02

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	polynomialsUtils "github.com/copperexchange/krypton-primitives/pkg/base/polynomials/utils"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

type Participant interface {
	integration.Participant

	IsSignatureAggregator() bool
}

type SigningKeyShare[K bls.KeySubGroup] struct {
	Share     curves.Scalar
	PublicKey *bls.PublicKey[K]

	_ types.Incomparable
}

func (s *SigningKeyShare[K]) Validate() error {
	if s == nil {
		return errs.NewIsNil("signing key share is nil")
	}
	if s.Share.IsZero() {
		return errs.NewIsZero("share can't be zero")
	}
	if err := s.PublicKey.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "public key is invalid")
	}
	return nil
}

type PublicKeyShares[K bls.KeySubGroup] struct {
	PublicKey *bls.PublicKey[K]
	SharesMap map[types.IdentityHash]curves.PairingPoint

	_ types.Incomparable
}

func (p *PublicKeyShares[K]) Validate(cohortConfig *integration.CohortConfig) error {
	if p == nil {
		return errs.NewIsNil("receiver is nil")
	}
	if p.PublicKey == nil {
		return errs.NewIsNil("public key is nil")
	}
	curve := p.PublicKey.Y.Curve()
	if !bls12381.InCorrectSubGroup[K](p.PublicKey.Y) {
		return errs.NewInvalidCurve("key subgroup is different than public key subgroup")
	}

	sharingIdToIdentityKey, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)
	sharingIds := make([]curves.Scalar, cohortConfig.Participants.Len())
	partialPublicKeys := make([]curves.Point, cohortConfig.Participants.Len())
	for i := 0; i < cohortConfig.Participants.Len(); i++ {
		sharingIds[i] = curve.ScalarField().New(uint64(i + 1))
		identityKey, exists := sharingIdToIdentityKey[i+1]
		if !exists {
			return errs.NewMissing("missing identity key for sharing id %d", i+1)
		}
		partialPublicKey, exists := p.SharesMap[identityKey.Hash()]
		if !exists {
			return errs.NewMissing("partial public key doesn't exist for id hash %x", identityKey.Hash())
		}
		if !bls12381.InCorrectSubGroup[K](partialPublicKey) {
			return errs.NewInvalidCurve("partial public key %d is in wrong subgroup", i)
		}
		partialPublicKeys[i] = partialPublicKey
	}
	evaluateAt := curve.ScalarField().New(0) // because f(0) would be the private key which means interpolating in the exponent should give us the public key
	reconstructedPublicKey, err := polynomialsUtils.InterpolateInTheExponent(curve, sharingIds, partialPublicKeys, evaluateAt)
	if err != nil {
		return errs.WrapFailed(err, "could not interpolate partial public keys in the exponent")
	}
	if !reconstructedPublicKey.Equal(p.PublicKey.Y) {
		return errs.NewVerificationFailed("reconstructed public key is incorrect")
	}
	return nil
}

func ConstructPrivateKey[K bls.KeySubGroup](threshold, n int, allParticipantIdKeys *hashset.HashSet[integration.IdentityKey], keyShares map[integration.IdentityKey]*SigningKeyShare[K]) (curves.Scalar, error) {
	if len(keyShares) <= 1 || len(keyShares) != threshold {
		return nil, errs.NewFailed("not enough key shares")
	}
	if allParticipantIdKeys == nil || allParticipantIdKeys.Len() <= 1 {
		return nil, errs.NewFailed("not enough participant keys")
	}
	for _, keyShare := range keyShares {
		if err := keyShare.Validate(); err != nil {
			return nil, errs.WrapVerificationFailed(err, "key share is invalid")
		}
	}
	var curve curves.Curve
	for idKey, keyShare := range keyShares {
		if err := keyShare.Validate(); err != nil {
			return nil, errs.WrapVerificationFailed(err, "key share is invalid")
		}
		curve = idKey.PublicKey().Curve()
		break
	}
	if curve == nil {
		return nil, errs.NewFailed("failed to get the curve")
	}
	shamirDealer, err := shamir.NewDealer(threshold, n, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create shamir dealer")
	}
	shares := make([]*shamir.Share, len(keyShares))
	shareIndex := 0
	for idKey, keyShare := range keyShares {
		_, _, sharingId := integration.DeriveSharingIds(idKey, allParticipantIdKeys)
		shares[shareIndex] = &shamir.Share{
			Id:    sharingId,
			Value: keyShare.Share,
		}
		shareIndex++
	}
	recoveredPrivateKey, err := shamirDealer.Combine(shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to combine shares")
	}
	recoveredPublicKey := curve.ScalarBaseMult(recoveredPrivateKey)
	for _, keyShare := range keyShares {
		if !recoveredPublicKey.Equal(keyShare.PublicKey.Y) {
			return nil, errs.NewVerificationFailed("reconstructed public key is incorrect")
		}
	}
	return recoveredPrivateKey, nil
}

type Shard[K bls.KeySubGroup] struct {
	SigningKeyShare *SigningKeyShare[K]
	PublicKeyShares *PublicKeyShares[K]

	_ types.Incomparable
}

func (s *Shard[K]) Validate(cohortConfig *integration.CohortConfig) error {
	if err := s.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "invalid public key shares map")
	}
	return nil
}

type PartialSignature[S bls.SignatureSubGroup] struct {
	SigmaI    *bls.Signature[S]
	SigmaPOPI *bls.Signature[S]
	POP       *bls.ProofOfPossession[S]

	_ types.Incomparable
}
