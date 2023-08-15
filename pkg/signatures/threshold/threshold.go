package threshold

import (
	"errors"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
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

func (p *PublicKeyShares) Validate() error {
	derivedPublicKey := p.Curve.Point().Identity()
	for _, share := range p.SharesMap {
		derivedPublicKey = derivedPublicKey.Add(share)
	}
	if !derivedPublicKey.Equal(p.PublicKey) {
		return errors.New("public key shares can't be combined to the entire public key")
	}
	return nil
}
