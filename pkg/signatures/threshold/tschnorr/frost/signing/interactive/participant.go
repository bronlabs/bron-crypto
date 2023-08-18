package interactive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/signing/aggregation"
)

var _ frost.Participant = (*Cosigner)(nil)

type Cosigner struct {
	prng io.Reader

	MyIdentityKey integration.IdentityKey
	MySharingId   int
	Shard         *frost.Shard

	CohortConfig           *integration.CohortConfig
	SharingIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToSharingId map[helper_types.IdentityHash]int
	SessionParticipants    *hashset.HashSet[integration.IdentityKey]

	round int
	state *State

	_ helper_types.Incomparable
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
	for _, signatureAggregator := range ic.CohortConfig.SignatureAggregators.Iter() {
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

	_ helper_types.Incomparable
}

func NewInteractiveCosigner(identityKey integration.IdentityKey, sessionParticipants *hashset.HashSet[integration.IdentityKey], shard *frost.Shard, cohortConfig *integration.CohortConfig, prng io.Reader) (*Cosigner, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.PreSignatureComposer != nil {
		return nil, errs.NewVerificationFailed("can't set presignature composer if cosigner is interactive")
	}
	if shard == nil {
		return nil, errs.NewVerificationFailed("shard is nil")
	}
	if err := shard.SigningKeyShare.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate signing key share")
	}

	if sessionParticipants == nil {
		return nil, errs.NewIsNil("invalid number of session participants")
	}
	if sessionParticipants.Len() != cohortConfig.Threshold {
		return nil, errs.NewIncorrectCount("invalid number of session participants")
	}
	for _, sessionParticipant := range sessionParticipants.Iter() {
		if !cohortConfig.IsInCohort(sessionParticipant) {
			return nil, errs.NewInvalidArgument("invalid session participant")
		}
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
