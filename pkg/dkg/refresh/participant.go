package refresh

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/sharing/feldman"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	MyIdentityKey   integration.IdentityKey
	MySharingId     int
	UniqueSessionId []byte

	CohortConfig           *integration.CohortConfig
	sharingIdToIdentityKey map[int]integration.IdentityKey

	signingKeyShare *threshold.SigningKeyShare
	publicKeyShares *threshold.PublicKeyShares

	round      int
	transcript transcripts.Transcript
	state      *State

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
	shareVector []*feldman.Share
	commitments []curves.Point

	_ helper_types.Incomparable
}

func NewParticipant(uniqueSessionId []byte, identityKey integration.IdentityKey, signingKeyShare *threshold.SigningKeyShare, publicKeyShares *threshold.PublicKeyShares, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, identityKey, signingKeyShare, publicKeyShares, cohortConfig, prng); err != nil {
		return nil, errs.WrapInvalidArgument(err, "at least one argument is invalid")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KNOX_PEDERSEN_KEY_REFRESH-")
	}
	transcript.AppendMessages("key refresh", uniqueSessionId)

	result := &Participant{
		MyIdentityKey:   identityKey,
		UniqueSessionId: uniqueSessionId,
		prng:            prng,
		CohortConfig:    cohortConfig,

		publicKeyShares: publicKeyShares,
		signingKeyShare: signingKeyShare,

		round:      1,
		state:      &State{},
		transcript: transcript,
	}
	result.sharingIdToIdentityKey, _, result.MySharingId = integration.DeriveSharingIds(identityKey, result.CohortConfig.Participants)
	return result, nil
}

func validateInputs(uniqueSessionId []byte, identityKey integration.IdentityKey, signingKeyShare *threshold.SigningKeyShare, publicKeyShares *threshold.PublicKeyShares, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if err := signingKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "signing key share is invalid")
	}
	if err := publicKeyShares.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "public key shares are invlaid")
	}
	if !publicKeyShares.PublicKey.Equal(signingKeyShare.PublicKey) {
		return errs.NewFailed("public key of signing key share and public key shares are not equal")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if identityKey == nil {
		return errs.NewIsNil("my identity key is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewIsZero("sid length is zero")
	}
	return nil
}
