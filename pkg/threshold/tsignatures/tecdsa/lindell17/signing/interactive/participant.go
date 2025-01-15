package interactive_signing

import (
	"fmt"
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel = "KRYPTON_LINDELL17_SIGN-"
)

var (
	_ types.ThresholdSignatureParticipant = (*PrimaryCosigner)(nil)
	_ types.ThresholdSignatureParticipant = (*SecondaryCosigner)(nil)
)

type Cosigner struct {
	// Base participant
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.ThresholdSignatureProtocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	// Threshold participant
	mySharingId types.SharingID

	myShard *lindell17.Shard
	nic     compiler.Name
	quorum  ds.Set[types.IdentityKey]

	_ ds.Incomparable
}

type PrimaryCosignerState struct {
	k1           curves.Scalar
	bigR1Opening *hashcommitments.Opening
	bigR         curves.Point
	r            curves.Scalar
	bigR1        curves.Point

	_ ds.Incomparable
}

type PrimaryCosigner struct {
	Cosigner

	secondaryIdentityKey types.IdentityKey
	secondarySharingId   types.SharingID
	state                *PrimaryCosignerState

	_ ds.Incomparable
}

type SecondaryCosignerState struct {
	bigR1Commitment *hashcommitments.Commitment
	k2              curves.Scalar
	bigR2           curves.Point

	_ ds.Incomparable
}

type SecondaryCosigner struct {
	Cosigner

	primaryIdentityKey types.IdentityKey
	primarySharingId   types.SharingID
	state              *SecondaryCosignerState

	_ ds.Incomparable
}

func (cosigner *Cosigner) IdentityKey() types.IdentityKey {
	return cosigner.myAuthKey
}

func (cosigner *Cosigner) SharingId() types.SharingID {
	return cosigner.mySharingId
}

func (cosigner *Cosigner) Quorum() ds.Set[types.IdentityKey] {
	return cosigner.quorum
}

func newCosigner(sessionId []byte, myAuthKey types.AuthKey, hisIdentityKey types.IdentityKey, myShard *lindell17.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader, roundNo int) (cosigner *Cosigner, hisSharingId types.SharingID, err error) {
	err = validateInputs(sessionId, myAuthKey, hisIdentityKey, myShard, protocol, niCompiler, prng)
	if err != nil {
		return nil, 0, errs.WrapArgument(err, "invalid input arguments")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), niCompiler)
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, 0, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, 0, errs.NewMissing("could not find my sharing id")
	}
	hisSharingId, exists = sharingConfig.Reverse().Get(hisIdentityKey)
	if !exists {
		return nil, 0, errs.NewMissing("could not find the other party sharing id")
	}
	return &Cosigner{
		myAuthKey:   myAuthKey,
		Prng:        prng,
		Protocol:    protocol,
		Round:       roundNo,
		SessionId:   boundSessionId,
		Transcript:  transcript,
		mySharingId: mySharingId,
		myShard:     myShard,
		nic:         niCompiler,
	}, hisSharingId, nil
}

func NewPrimaryCosigner(sessionId []byte, myAuthKey types.AuthKey, secondaryIdentityKey types.IdentityKey, myShard *lindell17.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (primaryCosigner *PrimaryCosigner, err error) {
	cosigner, hisSharingId, err := newCosigner(sessionId, myAuthKey, secondaryIdentityKey, myShard, protocol, niCompiler, transcript, prng, 1)
	if err != nil {
		return nil, errs.WrapValidation(err, "could not construct primary cosigner")
	}
	primaryCosigner = &PrimaryCosigner{
		Cosigner:             *cosigner,
		secondaryIdentityKey: secondaryIdentityKey,
		secondarySharingId:   hisSharingId,
		state:                &PrimaryCosignerState{},
	}
	primaryCosigner.quorum = hashset.NewHashableHashSet[types.IdentityKey](myAuthKey, secondaryIdentityKey)
	if err := types.ValidateThresholdSignatureProtocol(primaryCosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not validate primary cosigner")
	}
	return primaryCosigner, nil
}

func NewSecondaryCosigner(sessionId []byte, myAuthKey types.AuthKey, primaryIdentityKey types.IdentityKey, myShard *lindell17.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (secondaryCosigner *SecondaryCosigner, err error) {
	cosigner, hisSharingId, err := newCosigner(sessionId, myAuthKey, primaryIdentityKey, myShard, protocol, niCompiler, transcript, prng, 2)
	if err != nil {
		return nil, errs.WrapValidation(err, "could not construct secondary cosigner")
	}
	secondaryCosigner = &SecondaryCosigner{
		Cosigner:           *cosigner,
		primaryIdentityKey: primaryIdentityKey,
		primarySharingId:   hisSharingId,
		state:              &SecondaryCosignerState{},
	}
	secondaryCosigner.quorum = hashset.NewHashableHashSet[types.IdentityKey](myAuthKey, primaryIdentityKey)
	if err := types.ValidateThresholdSignatureProtocol(secondaryCosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not validate secondary cosigner")
	}
	return secondaryCosigner, nil
}

func validateInputs(sessionId []byte, myAuthKey types.AuthKey, other types.IdentityKey, myShard *lindell17.Shard, protocol types.ThresholdSignatureProtocol, nic compiler.Name, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewArgument("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "threshold signature protocol config")
	}
	if err := types.ValidateAuthKey(myAuthKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateIdentityKey(other); err != nil {
		return errs.WrapValidation(err, "secondary identity key")
	}
	if err := myShard.Validate(protocol, myAuthKey, true); err != nil {
		return errs.WrapValidation(err, "my shard")
	}
	if !protocol.Participants().Contains(other) {
		return errs.NewMembership("secondary is not a participant")
	}
	if other.Equal(myAuthKey) {
		return errs.NewArgument("other and me are the same")
	}
	if !compilerUtils.CompilerIsSupported(nic) {
		return errs.NewType("compiler is not supported %s", nic)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
