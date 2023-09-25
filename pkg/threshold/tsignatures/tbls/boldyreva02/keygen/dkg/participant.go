package dkg

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Participant[K bls.KeySubGroup] struct {
	gennaroParty *gennaro.Participant
	inG1         bool
	round        int

	_ types.Incomparable
}

func (p *Participant[K]) GetIdentityKey() integration.IdentityKey {
	return p.gennaroParty.GetIdentityKey()
}

func (p *Participant[K]) GetSharingId() int {
	return p.gennaroParty.GetSharingId()
}

func (p *Participant[K]) GetCohortConfig() *integration.CohortConfig {
	return p.gennaroParty.GetCohortConfig()
}

func NewParticipant[K bls.KeySubGroup](uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader) (*Participant[K], error) {
	err := validateInputs[K](uniqueSessionId, cohortConfig, identityKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not validate inputs")
	}

	pointInK := new(K)
	inG1 := (*pointInK).CurveName() == bls12381.G1Name
	if (inG1 && cohortConfig.CipherSuite.Curve.Name() != bls12381.G1Name) || (!inG1 && cohortConfig.CipherSuite.Curve.Name() != bls12381.G2Name) {
		return nil, errs.NewInvalidCurve("cohort config curve mismatch with the declared subgroup")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_TBLS_KEYGEN-", nil)
	}
	transcript.AppendMessages("threshold bls dkg", uniqueSessionId)
	transcript.AppendMessages("keys subgroup", []byte(cohortConfig.CipherSuite.Curve.Name()))
	party, err := gennaro.NewParticipant(uniqueSessionId, identityKey, cohortConfig, prng, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct tbls dkg participant out of gennaro dkg participant")
	}
	return &Participant[K]{
		gennaroParty: party,
		inG1:         inG1,
		round:        1,
	}, nil
}

func validateInputs[K bls.KeySubGroup](uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identityKey integration.IdentityKey, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if cohortConfig.CipherSuite.Curve.Name() != (*new(K)).CurveName() {
		return errs.NewInvalidArgument("cohort config curve mismatch with the declared subgroup")
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
