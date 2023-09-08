package refresh

import (
	"io"

	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton/pkg/transcripts"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	sampler *hjky.Participant

	signingKeyShare *tsignatures.SigningKeyShare
	publicKeyShares *tsignatures.PublicKeyShares

	round      int
	transcript transcripts.Transcript

	_ types.Incomparable
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.sampler.GetIdentityKey()
}

func (p *Participant) GetSharingId() int {
	return p.sampler.GetSharingId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.sampler.GetCohortConfig()
}

func NewParticipant(uniqueSessionId []byte, identityKey integration.IdentityKey, signingKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PublicKeyShares, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, identityKey, signingKeyShare, publicKeyShares, cohortConfig, prng); err != nil {
		return nil, errs.WrapInvalidArgument(err, "at least one argument is invalid")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_HJKY_KEY_REFRESH-", nil)
	}
	transcript.AppendMessages("key refresh", uniqueSessionId)
	sampler, err := hjky.NewParticipant(uniqueSessionId, identityKey, cohortConfig, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct hjky zero share sampling participant")
	}

	result := &Participant{
		sampler: sampler,

		publicKeyShares: publicKeyShares,
		signingKeyShare: signingKeyShare,

		round:      1,
		transcript: transcript,
	}
	return result, nil
}

func validateInputs(uniqueSessionId []byte, identityKey integration.IdentityKey, signingKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PublicKeyShares, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("protocol config is nil")
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
	if !cohortConfig.IsInCohort(identityKey) {
		return errs.NewMembershipError("i am not in cohort")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewIsZero("sid length is zero")
	}
	return nil
}
