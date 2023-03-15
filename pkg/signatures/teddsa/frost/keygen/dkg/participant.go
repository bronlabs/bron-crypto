package dkg

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/pkg/errors"
)

type DKGParticipant struct {
	reader io.Reader

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

type State struct {
	r_i              curves.Scalar
	phi              []byte
	shareVector      []*sharing.ShamirShare
	commitmentVector *sharing.FeldmanVerifier
}

func NewDKGParticipant(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, reader io.Reader) (*DKGParticipant, error) {
	var err error
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrap(err, "cohort config is invalid")
	}
	result := &DKGParticipant{
		MyIdentityKey: identityKey,
		state:         &State{},
		reader:        reader,
		CohortConfig:  cohortConfig,
	}

	result.shamirIdToIdentityKey, result.MyShamirId, err = frost.DeriveShamirIds(identityKey, result.CohortConfig.Participants)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't derive shamir ids")
	}
	result.round = 1
	return result, nil
}
