package dkg

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/pkg/errors"
)

var _ frost.Participant = (*DKGParticipant)(nil)

type DKGParticipant struct {
	prng io.Reader

	MyIdentityKey      integration.IdentityKey
	MyShamirId         int
	myPartialPublicKey curves.Point
	secretKeyShare     curves.Scalar

	CohortConfig          *integration.CohortConfig
	shamirIdToIdentityKey map[int]integration.IdentityKey
	publicKey             curves.Point

	round int
	state *State
}

func (p *DKGParticipant) GetIdentityKey() integration.IdentityKey {
	return p.MyIdentityKey
}

func (p *DKGParticipant) GetShamirId() int {
	return p.MyShamirId
}

func (p *DKGParticipant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

func (p *DKGParticipant) IsSignatureAggregator() bool {
	for _, signatureAggregator := range p.CohortConfig.SignatureAggregators {
		if signatureAggregator.PublicKey().Equal(p.MyIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

type State struct {
	r_i         curves.Scalar
	phi         []byte
	shareVector []*sharing.ShamirShare
	commitments []curves.Point
}

func NewDKGParticipant(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader) (*DKGParticipant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrap(err, "cohort config is invalid")
	}
	result := &DKGParticipant{
		MyIdentityKey: identityKey,
		state:         &State{},
		prng:          prng,
		CohortConfig:  cohortConfig,
	}

	result.shamirIdToIdentityKey, _, result.MyShamirId = frost.DeriveShamirIds(identityKey, result.CohortConfig.Participants)
	result.round = 1
	return result, nil
}
