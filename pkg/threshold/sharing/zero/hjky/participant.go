package hjky

import (
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	PedersenParty *pedersen.Participant
	round         int
	transcript    transcripts.Transcript

	_ types.Incomparable
}

func (p *Participant) GetAuthKey() integration.AuthKey {
	return p.PedersenParty.GetAuthKey()
}

func (p *Participant) GetSharingId() int {
	return p.PedersenParty.GetSharingId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.PedersenParty.GetCohortConfig()
}

func NewParticipant(sid []byte, authKey integration.AuthKey, scalarField curves.ScalarField, threshold int, participants []integration.IdentityKey, prng io.Reader, transcript transcripts.Transcript) (*Participant, error) {
	cohortConfig := &integration.CohortConfig{
		CipherSuite: &integration.CipherSuite{
			Curve: scalarField.Curve(),
			Hash:  sha3.New256,
		},
		Participants: hashset.NewHashSet(participants),
		Protocol: &integration.ProtocolConfig{
			Threshold:            threshold,
			TotalParties:         len(participants),
			Name:                 protocols.DKLS24,
			SignatureAggregators: hashset.NewHashSet(participants),
		},
	}

	if err := validateInputs(sid, authKey, cohortConfig, prng); err != nil {
		return nil, errs.WrapInvalidArgument(err, "at least one argument is invalid")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_HJKY_ZERO_SHARE_SAMPLING-", nil)
	}
	transcript.AppendMessages("HJKY zero share session id", sid)

	pedersenParty, err := pedersen.NewParticipant(sid, authKey, cohortConfig, transcript, randomisedFischlin.Name, prng)
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
		return errs.NewMembership("i'm not in cohort")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewIsZero("sid length is zero")
	}
	return nil
}
