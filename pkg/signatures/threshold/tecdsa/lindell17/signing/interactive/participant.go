package interactive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel          = "COPPER_KNOX_LINDELL2017_INTERACTIVE_SIGN"
	transcriptSessionIdLabel = "COPPER_KNOX_LINDELL2017_INTERACTIVE_SIGN_SESSION_ID"
)

var (
	_ lindell17.Participant = (*PrimaryCosigner)(nil)
	_ lindell17.Participant = (*SecondaryCosigner)(nil)
)

type Cosigner struct {
	lindell17.Participant

	prng io.Reader
	// My Cohort config
	cohortConfig  *integration.CohortConfig
	sessionId     []byte
	transcript    transcripts.Transcript
	myIdentityKey integration.IdentityKey
	mySharingId   int
	myShard       *lindell17.Shard
	round         int

	_ helper_types.Incomparable
}

type PrimaryCosignerState struct {
	k1           curves.Scalar
	bigR1Witness []byte
	bigR         curves.Point
	r            curves.Scalar
	bigR1        curves.Point

	_ helper_types.Incomparable
}

type PrimaryCosigner struct {
	Cosigner

	secondaryIdentityKey integration.IdentityKey
	secondarySharingId   int
	state                *PrimaryCosignerState

	_ helper_types.Incomparable
}

type SecondaryCosignerState struct {
	bigR1Commitment commitments.Commitment
	k2              curves.Scalar
	bigR2           curves.Point

	_ helper_types.Incomparable
}

type SecondaryCosigner struct {
	Cosigner

	primaryIdentityKey integration.IdentityKey
	primarySharingId   int
	state              *SecondaryCosignerState

	_ helper_types.Incomparable
}

func (cosigner *Cosigner) GetIdentityKey() integration.IdentityKey {
	return cosigner.myIdentityKey
}

func (cosigner *Cosigner) GetSharingId() int {
	return cosigner.mySharingId
}

func (cosigner *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return cosigner.cohortConfig
}

func (cosigner *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range cosigner.cohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(cosigner.myIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewPrimaryCosigner(myIdentityKey, secondaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (primaryCosigner *PrimaryCosigner, err error) {
	err = validatePrimaryInputs(myIdentityKey, secondaryIdentityKey, myShard, cohortConfig, sessionId, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)
	primaryCosigner = &PrimaryCosigner{
		Cosigner: Cosigner{
			myIdentityKey: myIdentityKey,
			mySharingId:   mySharingId,
			myShard:       myShard,
			cohortConfig:  cohortConfig,
			sessionId:     sessionId,
			transcript:    transcript,
			prng:          prng,
			round:         1,
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

func validateSecondaryInputs(myIdentityKey, secondaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if err := myShard.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate shard")
	}
	if myIdentityKey == nil {
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

func NewSecondaryCosigner(myIdentityKey, primaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (secondaryCosigner *SecondaryCosigner, err error) {
	err = validateSecondaryInputs(myIdentityKey, primaryIdentityKey, myShard, cohortConfig, sessionId, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	_, keyToId, mySharingId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)
	return &SecondaryCosigner{
		Cosigner: Cosigner{
			myIdentityKey: myIdentityKey,
			mySharingId:   mySharingId,
			myShard:       myShard,
			cohortConfig:  cohortConfig,
			sessionId:     sessionId,
			transcript:    transcript,
			prng:          prng,
			round:         1,
		},
		primaryIdentityKey: primaryIdentityKey,
		primarySharingId:   keyToId[primaryIdentityKey.Hash()],
		state:              &SecondaryCosignerState{},
	}, nil
}

func validatePrimaryInputs(myIdentityKey, primaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if err := myShard.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate shard")
	}
	if myIdentityKey == nil {
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
