package lindell22

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

type PartialSignature struct {
	R curves.Point
	S curves.Scalar

	_ helper_types.Incomparable
}

type Shard struct {
	SigningKeyShare *threshold.SigningKeyShare
	PublicKeyShares *threshold.PublicKeyShares

	_ helper_types.Incomparable
}

func (s *Shard) Validate(cohortConfig *integration.CohortConfig) error {
	if err := s.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "invalid public key shares map")
	}
	return nil
}

type PreSignature struct {
	K    curves.Scalar
	BigR map[helper_types.IdentityHash]curves.Point

	_ helper_types.Incomparable
}

type PreSignatureBatch struct {
	PreSignatures []*PreSignature

	_ helper_types.Incomparable
}
