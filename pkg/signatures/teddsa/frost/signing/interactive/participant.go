package interactive_signing

import (
	"io"
	"time"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
	"github.com/pkg/errors"
)

type InteractiveCosigner struct {
	CohortConfig          *integration.CohortConfig
	reader                io.Reader
	MyIdentityKey         integration.IdentityKey
	round                 int
	MyShamirId            int
	shamirIdToIdentityKey map[int]integration.IdentityKey
	identityKeyToShamirId map[integration.IdentityKey]int
	SigningKeyShare       *frost.SigningKeyShare
	state                 *State
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

func NewInteractiveCosigner(identityKey integration.IdentityKey, signingKeyShare *frost.SigningKeyShare, cohortConfig *integration.CohortConfig, reader io.Reader) (*InteractiveCosigner, error) {
	var err error
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrap(err, "cohort config is invalid")
	}
	time.Sleep(2 * time.Second)

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
		reader:          reader,
		state:           &State{},
	}

	result.shamirIdToIdentityKey, result.MyShamirId, err = frost.DeriveShamirIds(identityKey, result.CohortConfig.Participants)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't derive shamir ids")
	}
	result.identityKeyToShamirId = map[integration.IdentityKey]int{}
	for shamirId, identityKey := range result.shamirIdToIdentityKey {
		result.identityKeyToShamirId[identityKey] = shamirId
	}
	result.round = 1
	return result, nil
}
