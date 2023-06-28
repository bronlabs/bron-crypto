package dkg

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost"
)

var _ frost.Participant = (*DKGParticipant)(nil)

type DKGParticipant struct {
	pedersenParty *pedersen.Participant
}

func (p *DKGParticipant) GetIdentityKey() integration.IdentityKey {
	return p.pedersenParty.GetIdentityKey()
}

func (p *DKGParticipant) GetShamirId() int {
	return p.pedersenParty.GetShamirId()
}

func (p *DKGParticipant) GetCohortConfig() *integration.CohortConfig {
	return p.pedersenParty.GetCohortConfig()
}

func (p *DKGParticipant) IsSignatureAggregator() bool {
	return p.pedersenParty.GetCohortConfig().IsSignatureAggregator(p.GetIdentityKey())
}

func NewDKGParticipant(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader) (*DKGParticipant, error) {
	party, err := pedersen.NewParticipant(identityKey, cohortConfig, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct frost dkg participant out of pedersen dkg participant")
	}
	return &DKGParticipant{
		pedersenParty: party,
	}, nil
}
