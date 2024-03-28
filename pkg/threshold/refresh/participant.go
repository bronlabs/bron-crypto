package refresh

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_HJKY_KEY_REFRESH-"

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	types.Participant[types.ThresholdProtocol]

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
	transcript, sessionId, err := hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sampler, err := hjky.NewParticipant(sessionId, authKey, protocol, niCompiler, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct hjky zero share sampling participant")
	}

	result := &Participant{
		Participant: types.NewBaseParticipant(prng, protocol, 1, sessionId, transcript),
		sampler:     sampler,

		publicKeyShares: publicKeyShares,
		signingKeyShare: signingKeyShare,
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
	if err := types.ValidateThresholdProtocol(protocol); err != nil {
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
