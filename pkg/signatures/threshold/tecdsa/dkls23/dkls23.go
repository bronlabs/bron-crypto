package dkls23

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

type Participant interface {
	integration.Participant
	IsSignatureAggregator() bool
}

type (
	SigningKeyShare = threshold.SigningKeyShare
	PublicKeyShares = threshold.PublicKeyShares
	PairwiseSeeds   = zero.PairwiseSeeds
)

type PartialSignature struct {
	Ui curves.Scalar
	Wi curves.Scalar
	Ri curves.Point

	_ helper_types.Incomparable
}

type BaseOTConfig struct {
	AsSender   *vsot.SenderOutput
	AsReceiver *vsot.ReceiverOutput

	_ helper_types.Incomparable
}

type Shard struct {
	SigningKeyShare *SigningKeyShare
	PublicKeyShares *PublicKeyShares
	PairwiseSeeds   PairwiseSeeds
	PairwiseBaseOTs map[helper_types.IdentityHash]*BaseOTConfig

	_ helper_types.Incomparable
}

func (s *Shard) Validate(cohortConfig *integration.CohortConfig) error {
	if err := s.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "invalid public key shares map")
	}
	// TODO: ensure all pairwise seeds are in cohort, after hashset is incorporated.
	// TODO: ensure all pairwise base OTs seeds are in cohort, after hashset is incorporated.
	return nil
}
