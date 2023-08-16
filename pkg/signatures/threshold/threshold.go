package threshold

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/sharing"
)

type SigningKeyShare struct {
	Share     curves.Scalar
	PublicKey curves.Point
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
	if !s.PublicKey.IsOnCurve() {
		return errs.NewNotOnCurve("public key is not on curve")
	}
	return nil
}

type PublicKeyShares struct {
	Curve     curves.Curve
	PublicKey curves.Point
	SharesMap map[integration.IdentityHash]curves.Point
}

func (p *PublicKeyShares) Validate(cohortConfig *integration.CohortConfig) error {
	sharingIdToIdentityKey, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)
	sharingIds := make([]curves.Scalar, cohortConfig.TotalParties)
	partialPublicKeys := make([]curves.Point, cohortConfig.TotalParties)
	for i := 0; i < cohortConfig.TotalParties; i++ {
		sharingIds[i] = p.Curve.Scalar().New(i + 1)
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
	evaluateAt := p.Curve.Scalar().New(0) // because f(0) would be the private key which means interpolating in the exponent should give us the public key
	reconstructedPublicKey, err := sharing.InterpolateInTheExponent(p.Curve, sharingIds, partialPublicKeys, evaluateAt)
	if err != nil {
		return errs.WrapFailed(err, "could not interpolate partial public keys in the exponent")
	}
	if !reconstructedPublicKey.Equal(p.PublicKey) {
		return errs.NewVerificationFailed("reconstructed public key is incorrect")
	}
	return nil
}
