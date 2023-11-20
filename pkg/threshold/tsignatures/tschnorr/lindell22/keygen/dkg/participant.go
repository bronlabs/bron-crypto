package dkg

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Participant struct {
	gennaroParty *gennaro.Participant
	round        int

	_ types.Incomparable
}

func (p *Participant) GetAuthKey() integration.AuthKey {
	return p.gennaroParty.GetAuthKey()
}

func (p *Participant) GetSharingId() int {
	return p.gennaroParty.GetSharingId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.gennaroParty.GetCohortConfig()
}

func NewParticipant(uniqueSessionId []byte, authKey integration.AuthKey, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	err := validateInputs(uniqueSessionId, authKey, cohortConfig, prng)
	if err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_TSCHNORR_LINDELL22_DKG", nil)
	}
	transcript.AppendMessages("lindell22 dkg", uniqueSessionId)
	party, err := gennaro.NewParticipant(uniqueSessionId, authKey, cohortConfig, prng, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct lindell22 dkg participant out of gennaro dkg participant")
	}
	return &Participant{
		gennaroParty: party,
		round:        1,
	}, nil
}

func validateInputs(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidArgument("unique session id is empty")
	}
	if identityKey == nil {
		return errs.NewInvalidArgument("identity key is nil")
	}
	if !cohortConfig.Participants.Contains(identityKey) {
		return errs.NewInvalidArgument("identity key is not in cohort config")
	}
	if prng == nil {
		return errs.NewInvalidArgument("prng is nil")
	}
	return nil
}
