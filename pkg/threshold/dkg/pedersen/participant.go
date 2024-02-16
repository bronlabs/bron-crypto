package pedersen

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_PEDERSEN_DKG-"

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	myIdentityKey types.AuthKey
	mySharingId   types.SharingID
	SessionId     []byte

	Protocol      types.ThresholdProtocol
	SharingConfig types.SharingConfig

	Transcript transcripts.Transcript
	round      int
	State      *State

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myIdentityKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.mySharingId
}

type State struct {
	ShareVector []*feldman.Share
	Commitments []curves.Point
	A_i0        curves.Scalar
	NiCompiler  compiler.NICompiler[batch_schnorr.Statement, batch_schnorr.Witness]

	_ ds.Incomparable
}

func NewParticipant(sessionId []byte, myAuthKey types.AuthKey, protocol types.ThresholdProtocol, nonInteractiveCompilerName compiler.Name, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	err := validateInputs(sessionId, myAuthKey, protocol, prng)
	if err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), nonInteractiveCompilerName)
	transcript, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	dlogPoKProtocol, err := batch_schnorr.NewSigmaProtocol(protocol.Curve().Generator(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog protocol")
	}
	niCompiler, err := compilerUtils.MakeNonInteractive(nonInteractiveCompilerName, dlogPoKProtocol, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create randomised fischlin compiler")
	}

	result := &Participant{
		myIdentityKey: myAuthKey,
		SessionId:     sessionId,
		State: &State{
			NiCompiler: niCompiler,
		},
		prng:          prng,
		SharingConfig: types.DeriveSharingConfig(protocol.Participants()),
		Protocol:      protocol,
		Transcript:    transcript,
		round:         1,
	}
	mySharingId, exists := result.SharingConfig.LookUpRight(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("couldn't find my sharing id")
	}
	result.mySharingId = mySharingId

	if err := types.ValidateThresholdProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}
	return result, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, prng io.Reader) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "cohort config is invalid")
	}
	if len(sessionId) == 0 {
		return errs.NewArgument("unique session id is empty")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
