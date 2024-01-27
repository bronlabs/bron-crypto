package dkls24

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

type Participant interface {
	integration.Participant
	IsSignatureAggregator() bool
}

type (
	SigningKeyShare = tsignatures.SigningKeyShare
	PublicKeyShares = tsignatures.PublicKeyShares
	PairwiseSeeds   = przs.PairwiseSeeds
)

type PartialSignature struct {
	Ui curves.Scalar
	Wi curves.Scalar
	Ri curves.Point

	_ types.Incomparable
}

type BaseOTConfig struct {
	AsSender   *ot.SenderRotOutput
	AsReceiver *ot.ReceiverRotOutput

	_ types.Incomparable
}

func (b *BaseOTConfig) Validate() error {
	if b.AsSender == nil || len(b.AsSender.Messages) == 0 {
		return errs.NewInvalidArgument("invalid base OT as sender")
	}
	if b.AsReceiver == nil || len(b.AsReceiver.ChosenMessages) == 0 || len(b.AsReceiver.Choices) == 0 {
		return errs.NewInvalidArgument("invalid base OT as receiver")
	}
	return nil
}

type Shard struct {
	SigningKeyShare *SigningKeyShare
	PublicKeyShares *PublicKeyShares
	PairwiseSeeds   PairwiseSeeds
	PairwiseBaseOTs map[types.IdentityHash]*BaseOTConfig

	_ types.Incomparable
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
	for _, baseOTseeds := range s.PairwiseBaseOTs {
		if err := baseOTseeds.Validate(); err != nil {
			return errs.WrapVerificationFailed(err, "invalid base OT seeds")
		}
	}
	return nil
}
