package lindell22

import (
	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures"
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
	SigningKeyShare *tsignatures.SigningKeyShare
	PublicKeyShares *tsignatures.PublicKeyShares

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
