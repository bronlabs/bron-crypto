package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel          = "COPPER_KRYPTON_LINDELL2017_INTERACTIVE_SIGN"
	transcriptSessionIdLabel = "COPPER_KRYPTON_LINDELL2017_INTERACTIVE_SIGN_SESSION_ID"
)

var (
	_ lindell17.Participant = (*PrimaryCosigner)(nil)
	_ lindell17.Participant = (*SecondaryCosigner)(nil)
)

type Cosigner struct {
	lindell17.Participant

	prng io.Reader
	// My Cohort config
	cohortConfig *integration.CohortConfig
	sessionId    []byte
	transcript   transcripts.Transcript
	myAuthKey    integration.AuthKey
	mySharingId  int
	myShard      *lindell17.Shard
	round        int

	_ types.Incomparable
}

type PrimaryCosignerState struct {
	k1           curves.Scalar
	bigR1Witness []byte
	bigR         curves.Point
	r            curves.Scalar
	bigR1        curves.Point

	_ types.Incomparable
}

type PrimaryCosigner struct {
	Cosigner

	secondaryIdentityKey integration.IdentityKey
	secondarySharingId   int
	state                *PrimaryCosignerState

	_ types.Incomparable
}

type SecondaryCosignerState struct {
	bigR1Commitment commitments.Commitment
	k2              curves.Scalar
	bigR2           curves.Point

	_ types.Incomparable
}

type SecondaryCosigner struct {
	Cosigner

	primaryIdentityKey integration.IdentityKey
	primarySharingId   int
	state              *SecondaryCosignerState

	_ types.Incomparable
}

func (cosigner *Cosigner) GetAuthKey() integration.AuthKey {
	return cosigner.myAuthKey
}

func (cosigner *Cosigner) GetSharingId() int {
	return cosigner.mySharingId
}

func (cosigner *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return cosigner.cohortConfig
}

func (cosigner *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range cosigner.cohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(cosigner.myAuthKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewPrimaryCosigner(myAuthKey integration.AuthKey, secondaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (primaryCosigner *PrimaryCosigner, err error) {
	err = validatePrimaryInputs(myAuthKey, secondaryIdentityKey, myShard, cohortConfig, sessionId, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)
	primaryCosigner = &PrimaryCosigner{
		Cosigner: Cosigner{
			myAuthKey:    myAuthKey,
			mySharingId:  mySharingId,
			myShard:      myShard,
			cohortConfig: cohortConfig,
			sessionId:    sessionId,
			transcript:   transcript,
			prng:         prng,
			round:        1,
		},
		secondaryIdentityKey: secondaryIdentityKey,
		secondarySharingId:   identityKeyToSharingId[secondaryIdentityKey.Hash()],
		state:                &PrimaryCosignerState{},
	}
	if !primaryCosigner.IsSignatureAggregator() {
		return nil, errs.NewFailed("interactive primary cosigner must be signature aggregator")
	}

	return primaryCosigner, nil
}

func validateSecondaryInputs(myAuthKey, secondaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if err := myShard.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate shard")
	}
	if myAuthKey == nil {
		return errs.NewIsNil("my identity key is nil")
	}
	if secondaryIdentityKey == nil {
		return errs.NewIsNil("primary identity key is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func NewSecondaryCosigner(myAuthKey integration.AuthKey, primaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (secondaryCosigner *SecondaryCosigner, err error) {
	err = validateSecondaryInputs(myAuthKey, primaryIdentityKey, myShard, cohortConfig, sessionId, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	_, keyToId, mySharingId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)
	return &SecondaryCosigner{
		Cosigner: Cosigner{
			myAuthKey:    myAuthKey,
			mySharingId:  mySharingId,
			myShard:      myShard,
			cohortConfig: cohortConfig,
			sessionId:    sessionId,
			transcript:   transcript,
			prng:         prng,
			round:        1,
		},
		primaryIdentityKey: primaryIdentityKey,
		primarySharingId:   keyToId[primaryIdentityKey.Hash()],
		state:              &SecondaryCosignerState{},
	}, nil
}

func validatePrimaryInputs(myAuthKey integration.AuthKey, primaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if err := myShard.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate shard")
	}
	if myAuthKey == nil {
		return errs.NewIsNil("my identity key is nil")
	}
	if primaryIdentityKey == nil {
		return errs.NewIsNil("primary identity key is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
