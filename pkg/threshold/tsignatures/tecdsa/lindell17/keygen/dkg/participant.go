package dkg

import (
	"fmt"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lpdl"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
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
	myBigQWitness     commitments.Witness
	myPaillierPk      *paillier.PublicKey
	myPaillierSk      *paillier.SecretKey
	myRPrime          *saferith.Nat
	myRDoublePrime    *saferith.Nat

	theirBigQCommitment          map[types.SharingID]commitments.Commitment
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
	myAuthKey         types.AuthKey
	mySharingId       types.SharingID
	mySigningKeyShare *tsignatures.SigningKeyShare
	publicKeyShares   *tsignatures.PartialPublicKeys
	protocol          types.ThresholdProtocol

	sharingConfig types.SharingConfig
	sessionId     []byte
	transcript    transcripts.Transcript
	prng          io.Reader
	nic           compiler.Name

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

func NewParticipant(sessionId []byte, myAuthKey types.AuthKey, mySigningKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, niCompiler compiler.Name, prng io.Reader, transcript transcripts.Transcript) (participant *Participant, err error) {
	err = validateInputs(sessionId, myAuthKey, mySigningKeyShare, publicKeyShares, protocol, niCompiler, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	transcript, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
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
		mySharingId:       mySharingId,
		mySigningKeyShare: mySigningKeyShare,
		publicKeyShares:   publicKeyShares,
		protocol:          protocol,
		sharingConfig:     sharingConfig,
		sessionId:         sessionId,
		transcript:        transcript,
		prng:              prng,
		round:             1,
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
