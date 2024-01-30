package tsignatures

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

type SigningKeyShare struct {
	Share     curves.Scalar
	PublicKey curves.Point

	_ types.Incomparable
}

func (s *SigningKeyShare) Validate() error {
	if s == nil {
		return errs.NewIsNil("signing key share is nil")
	}
	if s.Share.IsZero() {
		return errs.NewIsZero("share can't be zero")
	}
	if s.PublicKey.IsIdentity() {
		return errs.NewIsIdentity("public key can't be at infinity")
	}
	return nil
}

func ConstructPrivateKey(threshold, n int, allParticipantIdKeys *hashset.HashSet[integration.IdentityKey], keyShares map[integration.IdentityKey]*SigningKeyShare) (curves.Scalar, error) {
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
	for _, keyShare := range keyShares {
		if err := keyShare.Validate(); err != nil {
			return nil, errs.WrapVerificationFailed(err, "key share is invalid")
		}
		curve = keyShare.PublicKey.Curve()
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
		if !recoveredPublicKey.Equal(keyShare.PublicKey) {
			return nil, errs.NewVerificationFailed("reconstructed public key is incorrect")
		}
	}
	return recoveredPrivateKey, nil
}

type PublicKeyShares struct {
	PublicKey               curves.Point
	SharesMap               map[types.IdentityHash]curves.Point
	FeldmanCommitmentVector []curves.Point

	_ types.Incomparable
}

func (p *PublicKeyShares) Validate(cohortConfig *integration.CohortConfig) error {
	if p == nil {
		return errs.NewIsNil("receiver of this method is nil")
	}
	if len(p.FeldmanCommitmentVector) == 0 && len(p.FeldmanCommitmentVector) > len(p.SharesMap) {
		return errs.NewInvalidLength("feldman commitment vector length is invalid")
	}
	if len(p.SharesMap) == 0 {
		return errs.NewInvalidLength("shares map has no elements")
	}

	sharingIdToIdentityKey, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)
	sharingIds := make([]curves.Scalar, cohortConfig.Protocol.TotalParties)
	partialPublicKeys := make([]curves.Point, cohortConfig.Protocol.TotalParties)
	for i := 0; i < cohortConfig.Protocol.TotalParties; i++ {
		sharingIds[i] = p.PublicKey.Curve().ScalarField().New(uint64(i + 1))
		identityKey, exists := sharingIdToIdentityKey[i+1]
		if !exists {
			return errs.NewMissing("missing identity key for sharing id %d", i+1)
		}
		partialPublicKey, exists := p.SharesMap[identityKey.Hash()]
		if !exists {
			return errs.NewMissing("partial public key doesn't exist for id hash %x", identityKey.Hash())
		}
		partialPublicKeys[i] = partialPublicKey
	}
	evaluateAt := p.PublicKey.Curve().ScalarField().Zero() // because f(0) would be the private key which means interpolating in the exponent should give us the public key
	reconstructedPublicKey, err := polynomials.InterpolateInTheExponent(p.PublicKey.Curve(), sharingIds, partialPublicKeys, evaluateAt)
	if err != nil {
		return errs.WrapFailed(err, "could not interpolate partial public keys in the exponent")
	}
	if !reconstructedPublicKey.Equal(p.PublicKey) {
		return errs.NewVerificationFailed("reconstructed public key is incorrect")
	}
	return nil
}
