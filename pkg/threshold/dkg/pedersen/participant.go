package pedersen

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	MyAuthKey       integration.AuthKey
	MySharingId     int
	UniqueSessionId []byte

	CohortConfig            *integration.CohortConfig
	SharingIdToIdentityKey  map[int]integration.IdentityKey
	IdentityHashToSharingId map[types.IdentityHash]int

	Transcript transcripts.Transcript
	round      int
	State      *State

	_ types.Incomparable
}

func (p *Participant) GetAuthKey() integration.AuthKey {
	return p.MyAuthKey
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
	NiCompiler  compiler.NICompiler[batch_schnorr.Statement, batch_schnorr.Witness]

	_ types.Incomparable
}

func NewParticipant(uniqueSessionId []byte, authKey integration.AuthKey, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, nonInteractiveCompilerName compiler.Name, prng io.Reader) (*Participant, error) {
	err := validateInputs(uniqueSessionId, authKey, cohortConfig, prng)
	if err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_PEDERSEN_DKG-", nil)
	}
	transcript.AppendMessages("dkg", uniqueSessionId)

	protocol, err := batch_schnorr.NewSigmaProtocol(cohortConfig.CipherSuite.Curve.Generator(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog protocol")
	}
	niCompiler, err := compilerUtils.MakeNonInteractive(nonInteractiveCompilerName, protocol, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create randomised fischlin compiler")
	}

	result := &Participant{
		MyAuthKey:       authKey,
		UniqueSessionId: uniqueSessionId,
		State: &State{
			NiCompiler: niCompiler,
		},
		prng:         prng,
		CohortConfig: cohortConfig,
		Transcript:   transcript,
	}
	result.SharingIdToIdentityKey, result.IdentityHashToSharingId, result.MySharingId = integration.DeriveSharingIds(authKey, result.CohortConfig.Participants)
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
