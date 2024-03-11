package hjky

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_HJKY_ZERO_SAMPLE-"

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	PedersenParty *pedersen.Participant

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.PedersenParty.IdentityKey()
}

func (p *Participant) SharingId() types.SharingID {
	return p.PedersenParty.SharingId()
}

func NewParticipant(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(sessionId, authKey, protocol, prng); err != nil {
		return nil, errs.WrapArgument(err, "at least one argument is invalid")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), niCompiler)
	transcript, sessionId, err := hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	pedersenParty, err := pedersen.NewParticipant(sessionId, authKey, protocol, niCompiler, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct pedersen party")
	}

	result := &Participant{
		PedersenParty: pedersenParty,
	}
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
		return errs.WrapValidation(err, "threhsold protocol config is invalid")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewIsZero("sessionId length is zero")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("authKey and participants have different curves")
	}
	return nil
}
