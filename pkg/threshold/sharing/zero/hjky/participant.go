package hjky

import (
	"fmt"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	feldman_vss "github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
)

const transcriptLabel = "KRYPTON_HJKY_ZERO_SAMPLE-"

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	MyAuthKey   types.AuthKey
	MySharingId types.SharingID
	SharingCfg  types.SharingConfig
	Protocol    types.ThresholdProtocol
	Prng        io.Reader
	Round       int
	State       *State
}

type State struct {
	feldmanScheme       *feldman_vss.Scheme
	feldmanShare        *feldman_vss.Share
	feldmanVerification []curves.Point
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyAuthKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}

func NewParticipant(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, tape transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(sessionId, authKey, protocol, tape, prng); err != nil {
		return nil, errs.WrapArgument(err, "at least one argument is invalid")
	}

	dst := fmt.Sprintf("%s-%s-", transcriptLabel, protocol.Curve().Name())
	tape.AppendMessages("protocol", []byte(dst))
	tape.AppendMessages("sessionId", sessionId)

	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, ok := sharingCfg.Reverse().Get(authKey)
	if !ok {
		return nil, errs.NewFailed("invalid auth key")
	}

	feldmanScheme, err := feldman_vss.NewScheme(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to initialize Feldman-VSS")
	}

	p := &Participant{
		MyAuthKey:   authKey,
		MySharingId: mySharingId,
		SharingCfg:  sharingCfg,
		Protocol:    protocol,
		Prng:        prng,
		Round:       1,
		State: &State{
			feldmanScheme: feldmanScheme,
		},
	}
	if err := types.ValidateThresholdProtocol(p, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}

	return p, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, tape transcripts.Transcript, prng io.Reader) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "threshold protocol config is invalid")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if tape == nil {
		return errs.NewIsNil("tape is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewIsZero("sessionId length is zero")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("authKey and participants have different curves")
	}
	return nil
}
