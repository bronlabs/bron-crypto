package jf

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

// To get H for Pedersen commitments, we'll hash concatenation of below and provided sessionId to the curve.
// We assume that the hash to curve returns a uniformly random point. Look into hash2curve package and rfc.
// We assume that it is not possible to get discrete log of the resulting H wrt G designated by a curve.
// If you are not happy with the 2nd assumption, then you should add rounds to agree on H. We recommend using `agreeonrandom` package to derive a random sessionId (which normally only has to be unique) and pass it to the constructor.
const (
	NothingUpMySleeve = "COPPER_KRYPTON_JF_SOMETHING_UP_MY_SLEEVE-"
	transcriptLabel   = "COPPER_KRYPTON_JF-"
)

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	// Base participant
	myAuthKey  types.AuthKey
	Protocol   types.ThresholdProtocol
	Prng       io.Reader
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	// Threshold participant
	mySharingId   types.SharingID
	SharingConfig types.SharingConfig

	H curves.Point

	state *State

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.mySharingId
}

type State struct {
	myPartialSecretShare   *pedersen.Share
	commitments            []curves.Point
	commitmentsProof       compiler.NIZKPoKProof
	secretKeyShare         curves.Scalar
	partialPublicKeyShares map[types.SharingID]curves.Point
	niCompiler             compiler.NICompiler[batch_schnorr.Statement, batch_schnorr.Witness]

	_ ds.Incomparable
}

func NewParticipant(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, niCompilerName compiler.Name, prng io.Reader, transcript transcripts.Transcript) (*Participant, error) {
	err := validateInputs(sessionId, authKey, protocol, prng)
	if err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), niCompilerName)
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	HMessage, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, []byte(NothingUpMySleeve))
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce dlog of H")
	}
	H, err := protocol.Curve().Hash(HMessage)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}

	batchSchnorrProtocol, err := batch_schnorr.NewSigmaProtocol(protocol.Curve().Generator(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create batch Schnorr protocol")
	}
	niCompiler, err := compilerUtils.MakeNonInteractive(niCompilerName, batchSchnorrProtocol, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, fmt.Sprintf("cannot create %s compiler", niCompilerName))
	}
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(authKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	result := &Participant{
		myAuthKey:   authKey,
		mySharingId: mySharingId,
		Prng:        prng,
		Protocol:    protocol,
		Round:       1,
		SessionId:   boundSessionId,
		Transcript:  transcript,
		state: &State{
			niCompiler: niCompiler,
		},
		H:             H,
		SharingConfig: sharingConfig,
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
		return errs.WrapValidation(err, "threshold protocol config is invalid")
	}
	if prng == nil {
		return errs.NewArgument("prng is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewArgument("invalid session id")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("authKey and participants have different curves")
	}
	return nil
}
