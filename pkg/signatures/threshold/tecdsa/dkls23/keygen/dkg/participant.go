package dkg

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen"
	zeroSetup "github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/setup"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/dkls23"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
)

type Participant struct {
	PedersenParty     *pedersen.Participant
	ZeroSamplingParty *zeroSetup.Participant

	state *state
}

type state struct {
	signingKeyShare *dkls23.SigningKeyShare
	publicKeyShares *dkls23.PublicKeyShares
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.PedersenParty.GetIdentityKey()
}

func (p *Participant) GetShamirId() int {
	return p.PedersenParty.GetShamirId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.PedersenParty.GetCohortConfig()
}

func NewParticipant(identityKey integration.IdentityKey, pedersenSessionId []byte, zeroSamplingSessionId []byte, cohortConfig *integration.CohortConfig, prng io.Reader) (*Participant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	// TODO: refactor pedersen to use transcripts - you can do it for sid
	pedersenParty, err := pedersen.NewParticipant(pedersenSessionId, identityKey, cohortConfig, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct dkls23 dkg participant out of pedersen dkg participant")
	}
	zeroSamplingParty, err := zeroSetup.NewParticipant(cohortConfig.CipherSuite.Curve, zeroSamplingSessionId, identityKey, cohortConfig.Participants, nil, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not contrust dkls23 dkg participant out of zero samplig setup participant")
	}
	return &Participant{
		PedersenParty:     pedersenParty,
		ZeroSamplingParty: zeroSamplingParty,
	}, nil
}
