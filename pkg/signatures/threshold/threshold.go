package threshold

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
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

	if s.PublicKey.CurveName() == edwards25519.Name {
		edwardsPoint, ok := s.PublicKey.(*edwards25519.Point)
		if !ok {
			return errs.NewDeserializationFailed("curve is ed25519 but the public key could not be type casted to the correct point struct")
		}
		// this check is not part of the ed25519 standard yet if the public key is of small order then the signature will be susceptibe
		// to a key substitution attack (specifically, it won't have message bound security). Refer to section 5.4 of https://eprint.iacr.org/2020/823.pdf and https://eprint.iacr.org/2020/1244.pdf
		if edwardsPoint.IsSmallOrder() {
			return errs.NewFailed("public key is small order")
		}
	}
	return nil
}

type PublicKeyShares struct {
	Curve     curves.Curve
	PublicKey curves.Point
	SharesMap map[integration.IdentityHash]curves.Point
}

// TODO: write down validation (lambda trick)
// func (p *PublicKeyShares) Validate() error {
// 	derivedPublicKey := p.Curve.Point().Identity()
// 	for _, share := range p.SharesMap {
// 		derivedPublicKey = derivedPublicKey.Add(share)
// 	}
// 	if !derivedPublicKey.Equal(p.PublicKey) {
// 		return errors.New("public key shares can't be combined to the entire public key")
// 	}
// 	return nil
// }.
