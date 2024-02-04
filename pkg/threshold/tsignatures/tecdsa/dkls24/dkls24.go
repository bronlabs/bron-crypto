package dkls24

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
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
	AsSender   *vsot.SenderOutput
	AsReceiver *vsot.ReceiverOutput

	_ types.Incomparable
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
	return nil
}

type PreSignature struct {
	R         curves.Scalar
	Phi       curves.Scalar
	Zeta      curves.Scalar
	Cu        map[types.IdentityHash]curves.Scalar
	Cv        map[types.IdentityHash]curves.Scalar
	Du        map[types.IdentityHash]curves.Scalar
	Dv        map[types.IdentityHash]curves.Scalar
	Psi       map[types.IdentityHash]curves.Scalar
	TheirBigR map[types.IdentityHash]curves.Point
}

type PreSignatureBatch struct {
	PreSignatures []*PreSignature
}
