package recovery

import (
	"fmt"
	"io"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
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

const transcriptLabel = "COPPER_KRYPTON_KEY_RECOVERY-"

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	// Base participant
	Prng     io.Reader
	Protocol types.ThresholdProtocol
	Round    int

	sampler                     *hjky.Participant
	sortedPresentRecoverersList []types.IdentityKey

	signingKeyShare *tsignatures.SigningKeyShare
	publicKeyShares *tsignatures.PartialPublicKeys

	lostPartyIdentityKey types.IdentityKey
	additiveShareOfZero  curves.Scalar

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.sampler.IdentityKey()
}

func (p *Participant) SharingId() types.SharingID {
	return p.sampler.SharingId()
}

func (p *Participant) IsRecoverer() bool {
	return !p.IdentityKey().Equal(p.lostPartyIdentityKey)
}

func NewRecoverer(sessionId []byte, authKey types.AuthKey, lostPartyIdentityKey types.IdentityKey, signingKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, presentRecoverers ds.Set[types.IdentityKey], niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateRecovererInputs(sessionId, authKey, lostPartyIdentityKey, signingKeyShare, publicKeyShares, protocol, presentRecoverers, prng); err != nil {
		return nil, errs.WrapArgument(err, "could not validate inputs")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), niCompiler)
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sampler, err := hjky.NewParticipant(boundSessionId, authKey, protocol, niCompiler, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampler")
	}
	presentRecoverersList := presentRecoverers.List()
	sort.Sort(types.ByPublicKey(presentRecoverersList))

	result := &Participant{
		Prng:                        prng,
		sampler:                     sampler,
		sortedPresentRecoverersList: presentRecoverersList,
		publicKeyShares:             publicKeyShares,
		signingKeyShare:             signingKeyShare,
		lostPartyIdentityKey:        lostPartyIdentityKey,
		Protocol:                    protocol,
		Round:                       1,
	}
	if err := types.ValidateThresholdProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct recoverer")
	}
	return result, nil
}

func validateRecovererInputs(sessionId []byte, authKey types.AuthKey, lostPartyIdentityKey types.IdentityKey, signingKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, presentRecoverers ds.Set[types.IdentityKey], prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsZero("sessionId length is zero")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "authKey")
	}
	if err := types.ValidateIdentityKey(lostPartyIdentityKey); err != nil {
		return errs.WrapValidation(err, "lost party identity Key")
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
	if authKey.Equal(lostPartyIdentityKey) {
		return errs.NewType("recoverer can't be lost party")
	}
	if !protocol.Participants().Contains(lostPartyIdentityKey) {
		return errs.NewMissing("lost party is not one of the participants")
	}
	if presentRecoverers.Contains(lostPartyIdentityKey) {
		return errs.NewType("recoverer can't be lost party")
	}
	if !presentRecoverers.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("present recoverer set is not a subset of all participants")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("authKey and participants have different curves")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), lostPartyIdentityKey) {
		return errs.NewCurve("authKey and lostPartyIdentityKey have different curves")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), presentRecoverers.List()...) {
		return errs.NewCurve("authKey and presentRecoverers have different curves")
	}
	if !curveutils.AllPointsOfSameCurve(signingKeyShare.PublicKey.Curve(), publicKeyShares.PublicKey) {
		return errs.NewCurve("authKey and lostPartyIdentityKey have different curves")
	}
	return nil
}

func NewLostParty(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, niCompiler compiler.Name, presentRecoverers ds.Set[types.IdentityKey], publicKeyShares *tsignatures.PartialPublicKeys, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateLostPartyInputs(sessionId, authKey, protocol, presentRecoverers, publicKeyShares, prng); err != nil {
		return nil, errs.WrapArgument(err, "could not validate inputs")
	}
	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), niCompiler)
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sampler, err := hjky.NewParticipant(boundSessionId, authKey, protocol, niCompiler, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampler")
	}
	presentRecoverersList := presentRecoverers.List()
	sort.Sort(types.ByPublicKey(presentRecoverersList))

	result := &Participant{
		Prng:                        prng,
		sampler:                     sampler,
		sortedPresentRecoverersList: presentRecoverersList,
		lostPartyIdentityKey:        authKey,
		publicKeyShares:             publicKeyShares,
		Protocol:                    protocol,
		Round:                       1,
	}
	if err := types.ValidateThresholdProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct lost party")
	}
	return result, nil
}

func validateLostPartyInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, presentRecoverers ds.Set[types.IdentityKey], publicKeyShares *tsignatures.PartialPublicKeys, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsZero("sessionId length is zero")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "authKey")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "threshold protocol")
	}
	if err := publicKeyShares.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "public key shares are invlaid")
	}
	if !presentRecoverers.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("present recoverer set is not a subset of all participants")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("authKey and participants have different curves")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), presentRecoverers.List()...) {
		return errs.NewCurve("authKey and presentRecoverers have different curves")
	}
	return nil
}
