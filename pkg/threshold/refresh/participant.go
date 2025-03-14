package refresh

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const transcriptLabel = "KRYPTON_HJKY_KEY_REFRESH-"

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	Protocol   types.ThresholdProtocol
	Round      int
	Transcript transcripts.Transcript

	sampler *hjky.Participant

	signingKeyShare *tsignatures.SigningKeyShare
	publicKeyShares *tsignatures.PartialPublicKeys

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.sampler.IdentityKey()
}

func (p *Participant) SharingId() types.SharingID {
	return p.sampler.SharingId()
}

func NewParticipant(sessionId []byte, authKey types.AuthKey, signingKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(sessionId, authKey, signingKeyShare, publicKeyShares, protocol, prng); err != nil {
		return nil, errs.WrapArgument(err, "at least one argument is invalid")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), niCompiler)
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sampler, err := hjky.NewParticipant(boundSessionId, authKey, protocol, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct hjky zero share sampling participant")
	}

	result := &Participant{
		sampler: sampler,

		publicKeyShares: publicKeyShares,
		signingKeyShare: signingKeyShare,
		Protocol:        protocol,

		Round:      1,
		Transcript: transcript,
	}
	if err := types.ValidateThresholdProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}
	return result, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, signingKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsZero("sessionId length is zero")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "authKey")
	}
	if !publicKeyShares.PublicKey.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
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
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("authKey and participants have different curves")
	}
	if !curveutils.AllPointsOfSameCurve(signingKeyShare.PublicKey.Curve(), publicKeyShares.PublicKey) {
		return errs.NewCurve("authKey and lostPartyIdentityKey have different curves")
	}
	return nil
}
