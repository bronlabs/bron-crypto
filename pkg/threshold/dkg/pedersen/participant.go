package pedersen

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	MyIdentityKey   integration.IdentityKey
	MySharingId     int
	UniqueSessionId []byte

	CohortConfig            *integration.CohortConfig
	SharingIdToIdentityKey  map[int]integration.IdentityKey
	IdentityHashToSharingId map[helper_types.IdentityHash]int

	Transcript transcripts.Transcript
	round      int
	State      *State

	_ helper_types.Incomparable
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) GetSharingId() int {
	return p.MySharingId
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

type State struct {
	ShareVector []*feldman.Share
	Commitments []curves.Point
	A_i0        curves.Scalar

	_ helper_types.Incomparable
}

func NewParticipant(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	err := validateInputs(uniqueSessionId, identityKey, cohortConfig, prng)
	if err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KNOX_PEDERSEN_DKG-")
	}
	transcript.AppendMessages("dkg", uniqueSessionId)
	result := &Participant{
		MyIdentityKey:   identityKey,
		UniqueSessionId: uniqueSessionId,
		State:           &State{},
		prng:            prng,
		CohortConfig:    cohortConfig,
		Transcript:      transcript,
	}
	result.SharingIdToIdentityKey, result.IdentityHashToSharingId, result.MySharingId = integration.DeriveSharingIds(identityKey, result.CohortConfig.Participants)
	result.round = 1
	return result, nil
}

func validateInputs(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidArgument("unique session id is empty")
	}
	if identityKey == nil {
		return errs.NewIsNil("my identity key is nil")
	}
	if !cohortConfig.Participants.Contains(identityKey) {
		return errs.NewInvalidArgument("identity key is not in cohort config")
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
