package hjky

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	PedersenParty *pedersen.Participant
	round         int
	transcript    transcripts.Transcript

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.PedersenParty.IdentityKey()
}

func (p *Participant) SharingId() types.SharingID {
	return p.PedersenParty.SharingId()
}

func NewParticipant(uniqueSessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, authKey, protocol, prng); err != nil {
		return nil, errs.WrapArgument(err, "at least one argument is invalid")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_HJKY_ZERO_SHARE_SAMPLING-", nil)
	}
	transcript.AppendMessages("HJKY zero share session id", uniqueSessionId)

	pedersenParty, err := pedersen.NewParticipant(uniqueSessionId, authKey, protocol, niCompiler, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct pedersen party")
	}

	result := &Participant{
		PedersenParty: pedersenParty,
		round:         1,
		transcript:    transcript,
	}
	if err := types.ValidateThresholdProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}
	return result, nil
}

func validateInputs(uniqueSessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, prng io.Reader) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "cohort config is invalid")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewIsZero("sid length is zero")
	}
	return nil
}
