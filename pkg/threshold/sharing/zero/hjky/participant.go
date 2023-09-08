package hjky

import (
	"io"

	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton/pkg/transcripts"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	PedersenParty *pedersen.Participant
	round         int
	transcript    transcripts.Transcript

	_ types.Incomparable
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.PedersenParty.GetIdentityKey()
}

func (p *Participant) GetSharingId() int {
	return p.PedersenParty.GetSharingId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.PedersenParty.GetCohortConfig()
}

func NewParticipant(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, identityKey, cohortConfig, prng); err != nil {
		return nil, errs.WrapInvalidArgument(err, "at least one argument is invalid")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_HJKY_ZERO_SHARE_SAMPLING-", nil)
	}
	transcript.AppendMessages("key refresh", uniqueSessionId)

	pedersenParty, err := pedersen.NewParticipant(uniqueSessionId, identityKey, cohortConfig, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct pedersen party")
	}

	result := &Participant{
		PedersenParty: pedersenParty,
		round:         1,
		transcript:    transcript,
	}
	return result, nil
}

func validateInputs(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if identityKey == nil {
		return errs.NewIsNil("my identity key is nil")
	}
	if !cohortConfig.IsInCohort(identityKey) {
		return errs.NewMembershipError("i'm not in cohort")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewIsZero("sid length is zero")
	}
	return nil
}
