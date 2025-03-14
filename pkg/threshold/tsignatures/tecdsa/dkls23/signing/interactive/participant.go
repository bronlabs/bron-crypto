package interactive

import (
	"fmt"
	"io"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/csprng"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23/signing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const transcriptLabel = "KRYPTON_TECDSA_DKLS23-"

type Cosigner struct {
	*signing.Participant

	state *signing.SignerState

	_ ds.Incomparable
}

func (ic *Cosigner) IsSignatureAggregator() bool {
	return ic.Protocol.Participants().Contains(ic.IdentityKey())
}

// NewCosigner constructs the interactive DKLs23 cosigner.
func NewCosigner(sessionId []byte, authKey types.AuthKey, quorum ds.Set[types.IdentityKey], shard *dkls23.Shard, protocol types.ThresholdSignatureProtocol, seededPrng csprng.CSPRNG, prng io.Reader, transcript transcripts.Transcript) (*Cosigner, error) {
	if err := validateInputs(sessionId, authKey, protocol, shard, quorum); err != nil {
		return nil, errs.WrapArgument(err, "could not validate input")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, nil)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	signingParticipant, err := signing.NewParticipant(authKey, prng, protocol, boundSessionId, transcript, quorum, shard)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct signing participant")
	}
	cosigner := &Cosigner{
		Participant: signingParticipant,
		state:       &signing.SignerState{},
	}
	cosigner.Participant.SeededPrng = seededPrng
	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a valid interactive dkls23 cosigner")
	}
	return cosigner, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdSignatureProtocol, shard *dkls23.Shard, quorum ds.Set[types.IdentityKey]) error {
	if len(sessionId) == 0 {
		return errs.NewLength("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "threshold signature protocol config")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "could not validate shard")
	}
	if quorum == nil {
		return errs.NewIsNil("invalid number of session participants")
	}
	if quorum.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants: %d", quorum.Size())
	}
	if quorum.Difference(protocol.Participants()).Size() != 0 {
		return errs.NewMembership("there are some present session participant that are not part of the protocol config")
	}
	if !quorum.Contains(authKey) {
		return errs.NewMembership("session participants do not include me")
	}
	return nil
}
