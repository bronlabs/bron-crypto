package noninteractive

import (
	"fmt"
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/signing"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_PREGEN_DKLS23-"

var _ types.ThresholdParticipant = (*PreGenParticipant)(nil) // only threshold piece of the protocol is important.

type PreGenParticipant struct {
	signing.Participant

	state *signing.SignerState

	_ ds.Incomparable
}

func NewPreGenParticipant(sessionId []byte, myAuthKey types.AuthKey, preSigners ds.Set[types.IdentityKey], myShard *dkls23.Shard, protocol types.ThresholdSignatureProtocol, transcript transcripts.Transcript, prng io.Reader, seededPrng csprng.CSPRNG) (participant *PreGenParticipant, err error) {
	if err := validateInputs(sessionId, myAuthKey, protocol, myShard, preSigners); err != nil {
		return nil, errs.WrapArgument(err, "could not validate input")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	signingParticipant, err := signing.NewParticipant(myAuthKey, prng, protocol, boundSessionId, transcript, preSigners, myShard)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct a lindell22 participant")
	}
	participant = &PreGenParticipant{
		Participant: *signingParticipant,
		state:       &signing.SignerState{},
	}

	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a lindell22 pregen participant")
	}

	return participant, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, shard *dkls23.Shard, preSigners ds.Set[types.IdentityKey]) error {
	if len(sessionId) == 0 {
		return errs.NewLength("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "threshold signature protocol config")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "could not validate shard")
	}
	if preSigners == nil {
		return errs.NewIsNil("preSigners")
	}
	if preSigners.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants: %d", preSigners.Size())
	}
	if preSigners.Difference(protocol.Participants()).Size() != 0 {
		return errs.NewMembership("there are some present session participant that are not part of the protocol config")
	}
	if !preSigners.Contains(authKey) {
		return errs.NewMembership("session participants do not include me")
	}
	return nil
}
