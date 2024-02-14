package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel          = "COPPER_KRYPTON_LINDELL2017_INTERACTIVE_SIGN"
	transcriptSessionIdLabel = "COPPER_KRYPTON_LINDELL2017_INTERACTIVE_SIGN_SESSION_ID"
)

var (
	_ types.ThresholdSignatureParticipant = (*PrimaryCosigner)(nil)
	_ types.ThresholdSignatureParticipant = (*SecondaryCosigner)(nil)
)

type Cosigner struct {
	prng        io.Reader
	protocol    types.ThresholdSignatureProtocol
	sessionId   []byte
	transcript  transcripts.Transcript
	myAuthKey   types.AuthKey
	mySharingId types.SharingID
	myShard     *lindell17.Shard
	nic         compiler.Name
	round       int

	_ ds.Incomparable
}

type PrimaryCosignerState struct {
	k1           curves.Scalar
	bigR1Witness []byte
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
	bigR1Commitment commitments.Commitment
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

func (cosigner *Cosigner) IsSignatureAggregator() bool {
	return cosigner.protocol.SignatureAggregators().Contains(cosigner.IdentityKey())
}

func NewPrimaryCosigner(sessionId []byte, myAuthKey types.AuthKey, secondaryIdentityKey types.IdentityKey, myShard *lindell17.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (primaryCosigner *PrimaryCosigner, err error) {
	err = validateInputs(sessionId, myAuthKey, secondaryIdentityKey, myShard, protocol, niCompiler, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.LookUpRight(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharign id")
	}
	theirSharingId, exists := sharingConfig.LookUpRight(secondaryIdentityKey)
	if !exists {
		return nil, errs.NewMissing("could not find the other party sharign id")
	}

	primaryCosigner = &PrimaryCosigner{
		Cosigner: Cosigner{
			myAuthKey:   myAuthKey,
			mySharingId: mySharingId,
			myShard:     myShard,
			protocol:    protocol,
			sessionId:   sessionId,
			transcript:  transcript,
			prng:        prng,
			nic:         niCompiler,
			round:       1,
		},
		secondaryIdentityKey: secondaryIdentityKey,
		secondarySharingId:   theirSharingId,
		state:                &PrimaryCosignerState{},
	}
	if !primaryCosigner.IsSignatureAggregator() {
		return nil, errs.NewFailed("interactive primary cosigner must be signature aggregator")
	}

	if err := types.ValidateThresholdSignatureProtocol(primaryCosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct primary cosigner")
	}

	return primaryCosigner, nil
}

func NewSecondaryCosigner(sessionId []byte, myAuthKey types.AuthKey, primaryIdentityKey types.IdentityKey, myShard *lindell17.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (secondaryCosigner *SecondaryCosigner, err error) {
	err = validateInputs(sessionId, myAuthKey, primaryIdentityKey, myShard, protocol, niCompiler, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.LookUpRight(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharign id")
	}
	theirSharingId, exists := sharingConfig.LookUpRight(primaryIdentityKey)
	if !exists {
		return nil, errs.NewMissing("could not find the other party sharign id")
	}
	secondaryCosigner = &SecondaryCosigner{
		Cosigner: Cosigner{
			myAuthKey:   myAuthKey,
			mySharingId: mySharingId,
			myShard:     myShard,
			protocol:    protocol,
			sessionId:   sessionId,
			transcript:  transcript,
			prng:        prng,
			round:       1,
			nic:         niCompiler,
		},
		primaryIdentityKey: primaryIdentityKey,
		primarySharingId:   theirSharingId,
		state:              &SecondaryCosignerState{},
	}
	if err := types.ValidateThresholdSignatureProtocol(secondaryCosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct secondary cosigner")
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
