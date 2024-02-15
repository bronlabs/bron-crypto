package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel          = "Lindell2022InteractiveSignCosignerStart"
	transcriptSessionIdLabel = "Lindell2022InteractiveSignSessionId"
)

var _ types.ThresholdSignatureParticipant = (*Cosigner)(nil)

type state struct {
	pid         []byte
	bigS        []byte
	k           curves.Scalar
	bigR        curves.Point
	bigRWitness commitments.Witness

	theirBigRCommitment ds.HashMap[types.IdentityKey, commitments.Commitment]

	_ ds.Incomparable
}

type Cosigner struct {
	przsParticipant *setup.Participant

	myAuthKey         types.AuthKey
	mySharingId       types.SharingID
	mySigningKeyShare *tsignatures.SigningKeyShare

	taproot             bool
	protocol            types.ThresholdSignatureProtocol
	sessionParticipants ds.HashSet[types.IdentityKey]
	sharingConfig       types.SharingConfig
	sid                 []byte
	round               int
	transcript          transcripts.Transcript
	nic                 compiler.Name
	prng                io.Reader

	state *state

	_ ds.Incomparable
}

func (p *Cosigner) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Cosigner) SharingId() types.SharingID {
	return p.mySharingId
}

func NewCosigner(myAuthKey types.AuthKey, sid []byte, sessionParticipants ds.HashSet[types.IdentityKey], myShard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, taproot bool, prng io.Reader) (p *Cosigner, err error) {
	if err := validateInputs(sid, myAuthKey, sessionParticipants, myShard, protocol, niCompiler, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sid)

	pid := myAuthKey.PublicKey().ToAffineCompressed()
	bigS := BigS(sessionParticipants)
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.LookUpRight(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("couldn't find my sharign id")
	}

	przsProtocol, err := types.NewMPCProtocol(protocol.Curve(), sessionParticipants)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't configure przs")
	}
	przsParticipant, err := setup.NewParticipant(sid, myAuthKey, przsProtocol, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot initialise PRZS participant")
	}

	cosigner := &Cosigner{
		przsParticipant:     przsParticipant,
		myAuthKey:           myAuthKey,
		mySharingId:         mySharingId,
		mySigningKeyShare:   myShard.SigningKeyShare,
		sharingConfig:       sharingConfig,
		protocol:            protocol,
		sid:                 sid,
		transcript:          transcript,
		sessionParticipants: sessionParticipants,
		taproot:             taproot,
		round:               1,
		prng:                prng,
		nic:                 niCompiler,
		state: &state{
			pid:  pid,
			bigS: bigS,
		},
	}

	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct lindell22 cosigner")
	}
	return cosigner, nil
}

func validateInputs(sid []byte, authKey types.AuthKey, sessionParticipants ds.HashSet[types.IdentityKey], shard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, nic compiler.Name, prng io.Reader) error {
	if len(sid) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "shard")
	}
	if sessionParticipants == nil {
		return errs.NewIsNil("session participants")
	}
	if sessionParticipants.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants")
	}
	if !sessionParticipants.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("session participant is not a subset of the protocol")
	}
	if !compilerUtils.CompilerIsSupported(nic) {
		return errs.NewType("compile is not supported: %s", nic)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
