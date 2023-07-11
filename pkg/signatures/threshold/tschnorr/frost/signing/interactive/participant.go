package interactive

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost/signing/aggregation"
)

var _ frost.Participant = (*InteractiveCosigner)(nil)

type InteractiveCosigner struct {
	prng io.Reader

	MyIdentityKey integration.IdentityKey
	MyShamirId    int
	Shard         *frost.Shard

	CohortConfig          *integration.CohortConfig
	ShamirIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToShamirId map[integration.IdentityKey]int
	SessionParticipants   []integration.IdentityKey

	round int
	state *State
}

func (ic *InteractiveCosigner) GetIdentityKey() integration.IdentityKey {
	return ic.MyIdentityKey
}

func (ic *InteractiveCosigner) GetShamirId() int {
	return ic.MyShamirId
}

func (ic *InteractiveCosigner) GetCohortConfig() *integration.CohortConfig {
	return ic.CohortConfig
}

func (ic *InteractiveCosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range ic.CohortConfig.SignatureAggregators {
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
}

func NewInteractiveCosigner(identityKey integration.IdentityKey, sessionParticipants []integration.IdentityKey, shard *frost.Shard, cohortConfig *integration.CohortConfig, prng io.Reader) (*InteractiveCosigner, error) {
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
	if len(sessionParticipants) != cohortConfig.Threshold {
		return nil, errs.NewIncorrectCount("invalid number of session participants")
	}
	for _, sessionParticipant := range sessionParticipants {
		if !cohortConfig.IsInCohort(sessionParticipant) {
			return nil, errs.NewInvalidArgument("invalid session participant")
		}
	}

	cosigner := &InteractiveCosigner{
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

	cosigner.ShamirIdToIdentityKey, cosigner.IdentityKeyToShamirId, cosigner.MyShamirId = integration.DeriveSharingIds(identityKey, cosigner.CohortConfig.Participants)

	cosigner.round = 1
	return cosigner, nil
}
