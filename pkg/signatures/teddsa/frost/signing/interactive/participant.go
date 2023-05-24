package interactive

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
	"github.com/pkg/errors"
)

var _ frost.Participant = (*InteractiveCosigner)(nil)

type InteractiveCosigner struct {
	reader io.Reader

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
	SmallD_i curves.Scalar
	D_i      curves.Point
	SmallE_i curves.Scalar
	E_i      curves.Point

	aggregation *aggregation.SignatureAggregatorParameters
}

func NewInteractiveCosigner(identityKey integration.IdentityKey, sessionParticipants []integration.IdentityKey, signingKeyShare *frost.SigningKeyShare, publicKeyShare *frost.PublicKeyShares, cohortConfig *integration.CohortConfig, reader io.Reader) (*InteractiveCosigner, error) {
	var err error
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrap(err, "cohort config is invalid")
	}
	if cohortConfig.PreSignatureComposer != nil {
		return nil, errors.New("can't set presignature composer if cosigner is interactive")
	}
	if err := signingKeyShare.Validate(); err != nil {
		return nil, errors.Wrap(err, "could not validate signing key share")
	}

	if sessionParticipants == nil || len(sessionParticipants) != cohortConfig.Threshold {
		return nil, errors.New("invalid number of session participants")
	}
	for _, sessionParticipant := range sessionParticipants {
		if !cohortConfig.IsInCohort(sessionParticipant) {
			return nil, errors.New("invalid session participant")
		}
	}

	cosigner := &InteractiveCosigner{
		MyIdentityKey:       identityKey,
		CohortConfig:        cohortConfig,
		SigningKeyShare:     signingKeyShare,
		PublicKeyShares:     publicKeyShare,
		SessionParticipants: sessionParticipants,
		reader:              reader,
		state:               &State{},
	}

	if cosigner.IsSignatureAggregator() {
		cosigner.state.aggregation = &aggregation.SignatureAggregatorParameters{}
	}

	cosigner.ShamirIdToIdentityKey, cosigner.IdentityKeyToShamirId, cosigner.MyShamirId, err = frost.DeriveShamirIds(identityKey, cosigner.CohortConfig.Participants)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't derive shamir ids")
	}

	cosigner.round = 1
	return cosigner, nil
}
