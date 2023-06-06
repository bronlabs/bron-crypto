package interactive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
	"github.com/pkg/errors"
)

var _ frost.Participant = (*InteractiveCosigner)(nil)

type InteractiveCosigner struct {
	prng io.Reader

	MyIdentityKey   integration.IdentityKey
	MyShamirId      int
	SigningKeyShare *frost.SigningKeyShare

	CohortConfig          *integration.CohortConfig
	PublicKeyShares       *frost.PublicKeyShares
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

func NewInteractiveCosigner(identityKey integration.IdentityKey, sessionParticipants []integration.IdentityKey, signingKeyShare *frost.SigningKeyShare, publicKeyShare *frost.PublicKeyShares, cohortConfig *integration.CohortConfig, prng io.Reader) (*InteractiveCosigner, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrapf(err, "%s cohort config is invalid", errs.VerificationFailed)
	}
	if cohortConfig.PreSignatureComposer != nil {
		return nil, errors.Errorf("%s can't set presignature composer if cosigner is interactive", errs.InvalidArgument)
	}
	if err := signingKeyShare.Validate(); err != nil {
		return nil, errors.Wrapf(err, "%s could not validate signing key share", errs.VerificationFailed)
	}

	if sessionParticipants == nil {
		return nil, errors.Errorf("%s invalid number of session participants", errs.IsNil)
	}
	if len(sessionParticipants) != cohortConfig.Threshold {
		return nil, errors.Errorf("%s invalid number of session participants", errs.IncorrectCount)
	}
	for _, sessionParticipant := range sessionParticipants {
		if !cohortConfig.IsInCohort(sessionParticipant) {
			return nil, errors.Errorf("%s invalid session participant", errs.Missing)
		}
	}

	cosigner := &InteractiveCosigner{
		MyIdentityKey:       identityKey,
		CohortConfig:        cohortConfig,
		SigningKeyShare:     signingKeyShare,
		PublicKeyShares:     publicKeyShare,
		SessionParticipants: sessionParticipants,
		prng:                prng,
		state:               &State{},
	}

	if cosigner.IsSignatureAggregator() {
		cosigner.state.aggregation = &aggregation.SignatureAggregatorParameters{}
	}

	cosigner.ShamirIdToIdentityKey, cosigner.IdentityKeyToShamirId, cosigner.MyShamirId = frost.DeriveShamirIds(identityKey, cosigner.CohortConfig.Participants)

	cosigner.round = 1
	return cosigner, nil
}
