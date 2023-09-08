package tsignatures

import (
	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/polynomials"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
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
	if !s.PublicKey.IsOnCurve() {
		return errs.NewMembershipError("public key is not on curve")
	}
	return nil
}

type PublicKeyShares struct {
	Curve                   curves.Curve
	PublicKey               curves.Point
	SharesMap               map[types.IdentityHash]curves.Point
	FeldmanCommitmentVector []curves.Point

	_ types.Incomparable
}

func (p *PublicKeyShares) Validate(cohortConfig *integration.CohortConfig) error {
	if p == nil {
		return errs.NewIsNil("receiver of this method is nil")
	}
	if p.Curve == nil {
		return errs.NewIsNil("curve is nil")
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
		sharingIds[i] = p.Curve.Scalar().New(uint64(i + 1))
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
	evaluateAt := p.Curve.Scalar().Zero() // because f(0) would be the private key which means interpolating in the exponent should give us the public key
	reconstructedPublicKey, err := polynomials.InterpolateInTheExponent(p.Curve, sharingIds, partialPublicKeys, evaluateAt)
	if err != nil {
		return errs.WrapFailed(err, "could not interpolate partial public keys in the exponent")
	}
	if !reconstructedPublicKey.Equal(p.PublicKey) {
		return errs.NewVerificationFailed("reconstructed public key is incorrect")
	}
	return nil
}
