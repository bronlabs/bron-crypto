package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/aggregation"
)

var _ frost.Participant = (*Cosigner)(nil)

type Cosigner struct {
	prng io.Reader

	MyIdentityKey integration.IdentityKey
	MySharingId   int
	Shard         *frost.Shard

	CohortConfig           *integration.CohortConfig
	SharingIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToSharingId map[types.IdentityHash]int
	SessionParticipants    *hashset.HashSet[integration.IdentityKey]

	round int
	state *State

	_ types.Incomparable
}

func (ic *Cosigner) GetIdentityKey() integration.IdentityKey {
	return ic.MyIdentityKey
}

func (ic *Cosigner) GetSharingId() int {
	return ic.MySharingId
}

func (ic *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return ic.CohortConfig
}

func (ic *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range ic.CohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(ic.MyIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

type State struct {
	d_i curves.Scalar
	D_i curves.Point
	e_i curves.Scalar
	E_i curves.Point

	aggregation *aggregation.SignatureAggregatorParameters

	_ types.Incomparable
}

func NewInteractiveCosigner(identityKey integration.IdentityKey, sessionParticipants *hashset.HashSet[integration.IdentityKey], shard *frost.Shard, cohortConfig *integration.CohortConfig, prng io.Reader) (*Cosigner, error) {
	err := validateInputs(identityKey, sessionParticipants, shard, cohortConfig, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
	}

	cosigner := &Cosigner{
		MyIdentityKey:       identityKey,
		CohortConfig:        cohortConfig,
		Shard:               shard,
		SessionParticipants: sessionParticipants,
		prng:                prng,
		state:               &State{},
	}

	if cosigner.IsSignatureAggregator() {
		cosigner.state.aggregation = &aggregation.SignatureAggregatorParameters{}
	}

	cosigner.SharingIdToIdentityKey, cosigner.IdentityKeyToSharingId, cosigner.MySharingId = integration.DeriveSharingIds(identityKey, cosigner.CohortConfig.Participants)

	cosigner.round = 1
	return cosigner, nil
}

func validateInputs(identityKey integration.IdentityKey, sessionParticipants *hashset.HashSet[integration.IdentityKey], shard *frost.Shard, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if shard == nil {
		return errs.NewVerificationFailed("shard is nil")
	}
	if err := shard.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate signing key share")
	}
	if identityKey == nil {
		return errs.NewIsNil("identity key is nil")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if sessionParticipants == nil {
		return errs.NewIsNil("invalid number of session participants")
	}
	if sessionParticipants.Len() != cohortConfig.Protocol.Threshold {
		return errs.NewIncorrectCount("invalid number of session participants")
	}
	for _, sessionParticipant := range sessionParticipants.Iter() {
		if !cohortConfig.IsInCohort(sessionParticipant) {
			return errs.NewInvalidArgument("invalid session participant")
		}
	}
	return nil
}
