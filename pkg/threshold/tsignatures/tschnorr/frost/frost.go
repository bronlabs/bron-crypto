package frost

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

type (
	SigningKeyShare = tsignatures.SigningKeyShare
	PublicKeyShares = tsignatures.PartialPublicKeys
)

var _ network.Message[types.ThresholdProtocol] = (*Shard)(nil)
var _ network.Message[types.ThresholdProtocol] = (*PartialSignature)(nil)

type Shard struct {
	SigningKeyShare *SigningKeyShare
	PublicKeyShares *PublicKeyShares

	_ ds.Incomparable
}

func (s *Shard) Validate(protocol types.ThresholdProtocol) error {
	if err := s.SigningKeyShare.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid public key shares map")
	}
	return nil
}

type PartialSignature struct {
	Zi curves.Scalar

	_ ds.Incomparable
}

func (ps *PartialSignature) Validate(protocol types.ThresholdProtocol) error {
	if ps.Zi == nil {
		return errs.NewIsNil("Zi is nil")
	}
	if ps.Zi.ScalarField().Curve() != protocol.Curve() {
		return errs.NewCurve("Zi curve %s does not match protocol curve %s", ps.Zi.ScalarField().Curve(), protocol.Curve())
	}
	if ps.Zi.IsZero() {
		return errs.NewIsZero("Zi")
	}
	return nil
}
