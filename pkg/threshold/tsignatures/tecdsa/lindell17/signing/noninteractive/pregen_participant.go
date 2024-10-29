package noninteractive_signing

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var _ types.ThresholdParticipant = (*PreGenParticipant)(nil)

type preGenParticipantState struct {
	k           curves.Scalar
	bigR        curves.Point
	bigROpening hashcommitments.Witness

	theirBigRCommitments ds.Map[types.IdentityKey, hashcommitments.Commitment]

	_ ds.Incomparable
}

type PreGenParticipant struct {
	myAuthKey   types.AuthKey
	mySharingId types.SharingID
	protocol    types.ThresholdProtocol
	sessionId   []byte
	transcript  transcripts.Transcript
	preSigners  ds.Set[types.IdentityKey]
	nic         compiler.Name
	round       int
	prng        io.Reader

	state *preGenParticipantState

	_ ds.Incomparable
}

func (p *PreGenParticipant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *PreGenParticipant) SharingId() types.SharingID {
	return p.mySharingId
}

const (
	transcriptLabel = "COPPER_KRYPTON_LINDELL17_NISIGN-"
)

func NewPreGenParticipant(sessionId []byte, transcript transcripts.Transcript, myAuthKey types.AuthKey, protocol types.ThresholdProtocol, preSigners ds.Set[types.IdentityKey], nic compiler.Name, prng io.Reader) (participant *PreGenParticipant, err error) {
	err = validateInputs(sessionId, myAuthKey, protocol, preSigners, nic, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "failed to validate inputs")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, nil)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("my sharing id")
	}

	participant = &PreGenParticipant{
		myAuthKey:   myAuthKey,
		protocol:    protocol,
		prng:        prng,
		mySharingId: mySharingId,
		sessionId:   boundSessionId,
		transcript:  transcript,
		preSigners:  preSigners,
		nic:         nic,
		round:       1,
		state:       &preGenParticipantState{},
	}
	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct pregen participant")
	}
	return participant, nil
}

func validateInputs(sessionId []byte, myAuthKey types.AuthKey, protocol types.ThresholdProtocol, preSigners ds.Set[types.IdentityKey], nic compiler.Name, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewArgument("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if err := types.ValidateAuthKey(myAuthKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if preSigners == nil {
		return errs.NewIsNil("preSigners")
	}
	if !preSigners.Contains(myAuthKey) {
		return errs.NewMembership("i am not a presigner")
	}
	if !preSigners.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("presigners are not a subset of total participants")
	}
	if !compilerUtils.CompilerIsSupported(nic) {
		return errs.NewType("compiler %s is not supported", nic)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
