package gennaro

import (
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
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
	NothingUpMySleeve = "COPPER_KRYPTON_GENNARO_DKG_SOMETHING_UP_MY_SLEEVE-"
	transcriptLabel   = "COPPER_KRYPTON_GENNARO_DKG-"
)

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	myAuthKey   types.AuthKey
	mySharingId types.SharingID

	Protocol      types.ThresholdProtocol
	SessionId     []byte
	SharingConfig types.SharingConfig

	H curves.Point

	round int
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
	transcript             transcripts.Transcript
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
	transcript, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	HMessage, err := hashing.HashChain(sha3.New256, sessionId, []byte(NothingUpMySleeve))
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
		myAuthKey: authKey,
		state: &State{
			niCompiler: niCompiler,
			transcript: transcript,
		},
		prng:          prng,
		Protocol:      protocol,
		H:             H,
		round:         1,
		SessionId:     sessionId,
		SharingConfig: sharingConfig,
		mySharingId:   mySharingId,
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
		return errs.WrapValidation(err, "cohort config is invalid")
	}
	if prng == nil {
		return errs.NewArgument("prng is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewArgument("invalid session id")
	}
	return nil
}
