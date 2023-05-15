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
	S   []int //present parties

	aggregation *aggregation.SignatureAggregatorParameters
}

func NewInteractiveCosigner(identityKey integration.IdentityKey, signingKeyShare *frost.SigningKeyShare, publicKeyShare *frost.PublicKeyShares, cohortConfig *integration.CohortConfig, reader io.Reader) (*InteractiveCosigner, error) {
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

	result := &InteractiveCosigner{
		MyIdentityKey:   identityKey,
		CohortConfig:    cohortConfig,
		SigningKeyShare: signingKeyShare,
		PublicKeyShares: publicKeyShare,
		reader:          reader,
		state:           &State{},
	}

	result.ShamirIdToIdentityKey, result.IdentityKeyToShamirId, result.MyShamirId, err = frost.DeriveShamirIds(identityKey, result.CohortConfig.Participants)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't derive shamir ids")
	}

	result.round = 1
	return result, nil
}
