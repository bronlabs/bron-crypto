package refresh

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	sampler *hjky.Participant

	protocol        types.ThresholdProtocol
	signingKeyShare *tsignatures.SigningKeyShare
	publicKeyShares *tsignatures.PartialPublicKeys

	round      int
	transcript transcripts.Transcript

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.sampler.IdentityKey()
}

func (p *Participant) SharingId() types.SharingID {
	return p.sampler.SharingId()
}

func NewParticipant(uniqueSessionId []byte, authKey types.AuthKey, signingKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, authKey, signingKeyShare, publicKeyShares, protocol, prng); err != nil {
		return nil, errs.WrapArgument(err, "at least one argument is invalid")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_HJKY_KEY_REFRESH-", nil)
	}
	transcript.AppendMessages("key refresh", uniqueSessionId)
	sampler, err := hjky.NewParticipant(uniqueSessionId, authKey, protocol, niCompiler, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct hjky zero share sampling participant")
	}

	result := &Participant{
		sampler: sampler,

		publicKeyShares: publicKeyShares,
		signingKeyShare: signingKeyShare,
		protocol:        protocol,

		round:      1,
		transcript: transcript,
	}
	if err := types.ValidateThresholdProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}
	return result, nil
}

func validateInputs(uniqueSessionId []byte, authKey types.AuthKey, signingKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, prng io.Reader) error {
	if len(uniqueSessionId) == 0 {
		return errs.NewIsZero("sid length is zero")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "authKey")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "threshold protocol")
	}
	if err := signingKeyShare.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "signing key shares")
	}
	if err := publicKeyShares.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "public key shares are invlaid")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}
