package frost

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

type Participant interface {
	integration.Participant
	IsSignatureAggregator() bool
}

type (
	SigningKeyShare = threshold.SigningKeyShare
	PublicKeyShares = threshold.PublicKeyShares
)

// TODO: Refactor and use this.
type Shard struct {
	SigningKeyShare *SigningKeyShare
	PublicKeyShares *PublicKeyShares

	_ helper_types.Incomparable
}

func (s *Shard) Validate(cohortConfig *integration.CohortConfig) error {
	if s == nil {
		return errs.NewIsNil("shard is nil")
	}
	if err := s.SigningKeyShare.Validate(); err != nil {
		return errs.WrapFailed(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(cohortConfig); err != nil {
		return errs.WrapFailed(err, "invalid public key shares")
	}
	if s.PublicKeyShares.PublicKey.IsIdentity() {
		return errs.NewIsIdentity("public key can't be at infinity")
	}
	if !s.PublicKeyShares.PublicKey.IsOnCurve() {
		return errs.NewMembershipError("public key is not on curve")
	}
	return nil
}

type PartialSignature struct {
	Zi curves.Scalar

	_ helper_types.Incomparable
}
