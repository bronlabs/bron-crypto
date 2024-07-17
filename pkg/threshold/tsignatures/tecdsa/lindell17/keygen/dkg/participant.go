package dkg

import (
	"fmt"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lpdl"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel = "COPPER_KRYPTON_LINDELL17_DKG-"
)

var _ types.ThresholdParticipant = (*Participant)(nil)

type State struct {
	myXPrime          curves.Scalar
	myXDoublePrime    curves.Scalar
	myBigQPrime       curves.Point
	myBigQDoublePrime curves.Point
	myBigQOpening     *hashcommitments.Opening
	myPaillierPk      *paillier.PublicKey
	myPaillierSk      *paillier.SecretKey
	myRPrime          *saferith.Nat
	myRDoublePrime    *saferith.Nat

	theirBigQCommitment          map[types.SharingID]*hashcommitments.Commitment
	theirBigQPrime               map[types.SharingID]curves.Point
	theirBigQDoublePrime         map[types.SharingID]curves.Point
	theirPaillierPublicKeys      ds.Map[types.IdentityKey, *paillier.PublicKey]
	theirPaillierEncryptedShares ds.Map[types.IdentityKey, *paillier.CipherText]

	lpProvers                map[types.SharingID]*lp.Prover
	lpVerifiers              map[types.SharingID]*lp.Verifier
	lpdlPrimeProvers         map[types.SharingID]*lpdl.Prover
	lpdlPrimeVerifiers       map[types.SharingID]*lpdl.Verifier
	lpdlDoublePrimeProvers   map[types.SharingID]*lpdl.Prover
	lpdlDoublePrimeVerifiers map[types.SharingID]*lpdl.Verifier

	_ ds.Incomparable
}

type Participant struct {
	// Base participant
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.ThresholdProtocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	// Threshold participant
	mySharingId   types.SharingID
	sharingConfig types.SharingConfig

	mySigningKeyShare *tsignatures.SigningKeyShare
	publicKeyShares   *tsignatures.PartialPublicKeys

	nic compiler.Name

	state *State

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.mySharingId
}

func NewParticipant(sessionId []byte, myAuthKey types.AuthKey, mySigningKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, niCompiler compiler.Name, prng io.Reader, transcript transcripts.Transcript) (participant *Participant, err error) {
	err = validateInputs(sessionId, myAuthKey, mySigningKeyShare, publicKeyShares, protocol, niCompiler, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("cannot find my sharing id")
	}

	participant = &Participant{
		myAuthKey:         myAuthKey,
		Prng:              prng,
		Protocol:          protocol,
		Round:             1,
		SessionId:         boundSessionId,
		Transcript:        transcript,
		mySharingId:       mySharingId,
		sharingConfig:     sharingConfig,
		mySigningKeyShare: mySigningKeyShare,
		publicKeyShares:   publicKeyShares,
		nic:               niCompiler,
		state:             &State{},
	}
	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "couldn't construct a valid participant")
	}
	return participant, nil
}

func validateInputs(sessionId []byte, myAuthKey types.AuthKey, mySigningKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, niCompiler compiler.Name, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewArgument("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
	}
	if err := types.ValidateAuthKey(myAuthKey); err != nil {
		return errs.WrapValidation(err, "my auth key")
	}
	if err := mySigningKeyShare.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "could not validate signing key share")
	}
	if err := publicKeyShares.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "could not validate public key shares")
	}
	if !compilerUtils.CompilerIsSupported(niCompiler) {
		return errs.NewType("compile is not supported: %s", niCompiler)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func (p *Participant) Run(router roundbased.MessageRouter) (*lindell17.Shard, error) {

	r1b := roundbased.NewBroadcastRound[*Round1Broadcast](p.IdentityKey(), 1, router)
	r2b := roundbased.NewBroadcastRound[*Round2Broadcast](p.IdentityKey(), 2, router)
	r3b := roundbased.NewBroadcastRound[*Round3Broadcast](p.IdentityKey(), 3, router)
	r4u := roundbased.NewUnicastRound[*Round4P2P](p.IdentityKey(), 4, router)
	r5u := roundbased.NewUnicastRound[*Round5P2P](p.IdentityKey(), 5, router)
	r6u := roundbased.NewUnicastRound[*Round6P2P](p.IdentityKey(), 6, router)
	r7u := roundbased.NewUnicastRound[*Round7P2P](p.IdentityKey(), 7, router)

	r1bOut, err := p.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "round 1 failed")
	}
	r1b.BroadcastOut() <- r1bOut

	r2bOut, err := p.Round2(<-r1b.BroadcastIn())
	if err != nil {
		return nil, errs.WrapFailed(err, "round 2 failed")
	}
	r2b.BroadcastOut() <- r2bOut

	r3bOut, err := p.Round3(<-r2b.BroadcastIn())
	if err != nil {
		return nil, errs.WrapFailed(err, "round 3 failed")
	}
	r3b.BroadcastOut() <- r3bOut

	r4uOut, err := p.Round4(<-r3b.BroadcastIn())
	if err != nil {
		return nil, errs.WrapFailed(err, "round 4 failed")
	}
	r4u.UnicastOut() <- r4uOut

	r5uOut, err := p.Round5(<-r4u.UnicastIn())
	if err != nil {
		return nil, errs.WrapFailed(err, "round 5 failed")
	}
	r5u.UnicastOut() <- r5uOut

	r6uOut, err := p.Round6(<-r5u.UnicastIn())
	if err != nil {
		return nil, errs.WrapFailed(err, "round 6 failed")
	}
	r6u.UnicastOut() <- r6uOut

	r7uOut, err := p.Round7(<-r6u.UnicastIn())
	if err != nil {
		return nil, errs.WrapFailed(err, "round 7 failed")
	}
	r7u.UnicastOut() <- r7uOut

	r8uOut, err := p.Round8(<-r7u.UnicastIn())
	if err != nil {
		return nil, errs.WrapFailed(err, "round 8 failed")
	}

	return r8uOut, nil
}
