package recovery

import (
	"io"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	sampler                     *hjky.Participant
	sortedPresentRecoverersList []integration.IdentityKey

	signingKeyShare *tsignatures.SigningKeyShare
	publicKeyShares *tsignatures.PublicKeyShares

	lostPartyIdentityKey integration.IdentityKey
	additiveShareOfZero  curves.Scalar

	round int

	_ types.Incomparable
}

func (p *Participant) GetAuthKey() integration.AuthKey {
	return p.sampler.GetAuthKey()
}

func (p *Participant) GetSharingId() int {
	return p.sampler.GetSharingId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.sampler.GetCohortConfig()
}

func (p *Participant) IsRecoverer() bool {
	return !types.Equals(p.lostPartyIdentityKey, p.GetAuthKey())
}

func NewRecoverer(uniqueSessionId []byte, authKey integration.AuthKey, lostPartyIdentityKey integration.IdentityKey, signingKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PublicKeyShares, cohortConfig *integration.CohortConfig, presentRecoverers *hashset.HashSet[integration.IdentityKey], transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, authKey, lostPartyIdentityKey, signingKeyShare, publicKeyShares, cohortConfig, prng); err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not validate inputs")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_KEY_RECOVERy-", nil)
	}
	transcript.AppendMessages("key recovery", uniqueSessionId)

	sampler, err := hjky.NewParticipant(uniqueSessionId, authKey, cohortConfig, transcript, prng)
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

func NewLostParty(uniqueSessionId []byte, authKey integration.AuthKey, publicKeyShares *tsignatures.PublicKeyShares, cohortConfig *integration.CohortConfig, presentRecoverers *hashset.HashSet[integration.IdentityKey], transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, authKey, authKey, nil, publicKeyShares, cohortConfig, prng); err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not validate inputs")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_KEY_RECOVERy-", nil)
	}
	transcript.AppendMessages("key recovery", uniqueSessionId)

	sampler, err := hjky.NewParticipant(uniqueSessionId, authKey, cohortConfig, transcript, prng)
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
		lostPartyIdentityKey:        authKey,
		round:                       1,
	}
	return result, nil
}

func validateInputs(uniqueSessionId []byte, identityKey, lostPartyIdentityKey integration.IdentityKey, signingKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PublicKeyShares, cohortConfig *integration.CohortConfig, prng io.Reader) error {
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
		return errs.NewMembership("I'm not in cohort")
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
