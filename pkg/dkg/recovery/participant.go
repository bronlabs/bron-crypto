package recovery

import (
	"io"
	"sort"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/types"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero/hjky"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	sampler                     *hjky.Participant
	sortedPresentRecoverersList []integration.IdentityKey

	signingKeyShare *threshold.SigningKeyShare
	publicKeyShares *threshold.PublicKeyShares

	lostPartyIdentityKey integration.IdentityKey
	additiveShareOfZero  curves.Scalar

	round int

	_ helper_types.Incomparable
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

func (p *Participant) IsRecoverer() bool {
	return !types.Equals(p.lostPartyIdentityKey, p.GetIdentityKey())
}

func NewRecoverer(uniqueSessionId []byte, identityKey, lostPartyIdentityKey integration.IdentityKey, signingKeyShare *threshold.SigningKeyShare, publicKeyShares *threshold.PublicKeyShares, cohortConfig *integration.CohortConfig, presentRecoverers *hashset.HashSet[integration.IdentityKey], transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, identityKey, lostPartyIdentityKey, signingKeyShare, publicKeyShares, cohortConfig, prng); err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not validate inputs")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KNOX_KEY_RECOVERy-")
	}
	transcript.AppendMessages("key recovery", uniqueSessionId)

	sampler, err := hjky.NewParticipant(uniqueSessionId, identityKey, cohortConfig, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampler")
	}
	presentRecoverersList := presentRecoverers.List()
	sort.Sort(integration.ByPublicKey(presentRecoverersList))

	result := &Participant{
		prng:                        prng,
		sampler:                     sampler,
		sortedPresentRecoverersList: presentRecoverersList,
		publicKeyShares:             publicKeyShares,
		signingKeyShare:             signingKeyShare,
		lostPartyIdentityKey:        lostPartyIdentityKey,
		round:                       1,
	}
	return result, nil
}

func NewLostParty(uniqueSessionId []byte, identityKey integration.IdentityKey, publicKeyShares *threshold.PublicKeyShares, cohortConfig *integration.CohortConfig, presentRecoverers *hashset.HashSet[integration.IdentityKey], transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, identityKey, identityKey, nil, publicKeyShares, cohortConfig, prng); err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not validate inputs")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KNOX_KEY_RECOVERy-")
	}
	transcript.AppendMessages("key recovery", uniqueSessionId)

	sampler, err := hjky.NewParticipant(uniqueSessionId, identityKey, cohortConfig, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampler")
	}
	presentRecoverersList := presentRecoverers.List()
	sort.Sort(integration.ByPublicKey(presentRecoverersList))

	result := &Participant{
		prng:                        prng,
		sampler:                     sampler,
		sortedPresentRecoverersList: presentRecoverersList,
		publicKeyShares:             publicKeyShares,
		lostPartyIdentityKey:        identityKey,
		round:                       1,
	}
	return result, nil
}

func validateInputs(uniqueSessionId []byte, identityKey, lostPartyIdentityKey integration.IdentityKey, signingKeyShare *threshold.SigningKeyShare, publicKeyShares *threshold.PublicKeyShares, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("protocol config is nil")
	}
	if identityKey == nil {
		return errs.NewIsNil("my identity key is nil")
	}
	if !cohortConfig.IsInCohort(identityKey) {
		return errs.NewMembershipError("I'm not in cohort")
	}
	if err := publicKeyShares.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "public key shares are invlaid")
	}
	if signingKeyShare != nil {
		if err := signingKeyShare.Validate(); err != nil {
			return errs.WrapVerificationFailed(err, "signing key share is invalid")
		}
		if !publicKeyShares.PublicKey.Equal(signingKeyShare.PublicKey) {
			return errs.NewFailed("public key of signing key share and public key shares are not equal")
		}
		if lostPartyIdentityKey == nil {
			return errs.NewIsNil("lost party identity key is nil")
		}
		if !cohortConfig.IsInCohort(lostPartyIdentityKey) {
			return errs.NewFailed("lost party identity key is not in cohort")
		}
		if types.Equals(lostPartyIdentityKey, identityKey) {
			return errs.NewFailed("i cannot be recoverer of my own share")
		}
	} else if !types.Equals(lostPartyIdentityKey, identityKey) {
		return errs.NewFailed("i have to identity as a lost party")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewIsZero("sid length is zero")
	}
	return nil
}
