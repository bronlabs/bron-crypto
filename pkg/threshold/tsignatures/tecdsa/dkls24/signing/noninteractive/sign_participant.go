package noninteractive

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

type Cosigner struct {
	signing.Participant

	ppm *dkls24.PreProcessingMaterial

	_ ds.Incomparable
}

func NewCosigner(myAuthKey types.AuthKey, myShard *dkls24.Shard, protocol types.ThresholdSignatureProtocol, ppm *dkls24.PreProcessingMaterial) (cosigner *Cosigner, err error) {
	if err := validateInputsSign([]byte("no session id for noninteractive"), myAuthKey, protocol, myShard, ppm); err != nil {
		return nil, errs.WrapArgument(err, "could not validate input")
	}
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	BaseParticipant := types.NewBaseParticipant(nil, protocol, 1, nil, nil)
	signingParticipant := signing.NewParticipant(BaseParticipant, myAuthKey, mySharingId, myShard, sharingConfig)
	participant := &Cosigner{
		Participant: *signingParticipant,
		ppm:         ppm,
	}

	if err := types.ValidateThresholdSignatureProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a valid interactive dkls24 cosigner")
	}

	return participant, nil
}

func validateInputsSign(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdSignatureProtocol, shard *dkls24.Shard, ppm *dkls24.PreProcessingMaterial) error {
	if ppm == nil {
		return errs.NewIsNil("ppm")
	}
	if err := validateInputs(sessionId, authKey, protocol, shard, ppm.PreSigners); err != nil {
		return err
	}
	if err := types.ValidateThresholdSignatureProtocol(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if err := ppm.Validate(authKey, protocol); err != nil {
		return errs.WrapValidation(err, "preprocessing material")
	}
	return nil
}
