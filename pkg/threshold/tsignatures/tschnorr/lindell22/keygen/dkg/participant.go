package dkg

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	gennaroParty *gennaro.Participant
	protocol     types.ThresholdProtocol
	round        int

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.gennaroParty.IdentityKey()
}

func (p *Participant) SharingId() types.SharingID {
	return p.gennaroParty.SharingId()
}

func NewParticipant(uniqueSessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	err := validateInputs(uniqueSessionId, authKey, protocol, prng)
	if err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_TSCHNORR_LINDELL22_DKG", nil)
	}
	transcript.AppendMessages("lindell22 dkg", uniqueSessionId)
	party, err := gennaro.NewParticipant(uniqueSessionId, authKey, protocol, niCompiler, prng, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct lindell22 dkg participant out of gennaro dkg participant")
	}
	participant := &Participant{
		gennaroParty: party,
		round:        1,
		protocol:     protocol,
	}
	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a lindell22 dkg participant")
	}
	return participant, nil
}

func validateInputs(uniqueSessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, prng io.Reader) error {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewArgument("unique session id is empty")
	}
	if prng == nil {
		return errs.NewArgument("prng is nil")
	}
	return nil
}
