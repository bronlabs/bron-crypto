package noninteractive

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/signing"
)

type Cosigner struct {
	*signing.Participant

	ppm *dkls23.PreProcessingMaterial

	_ ds.Incomparable
}

func NewCosigner(myAuthKey types.AuthKey, myShard *dkls23.Shard, protocol types.ThresholdSignatureProtocol, ppm *dkls23.PreProcessingMaterial) (cosigner *Cosigner, err error) {
	if err := validateInputsSign([]byte("no session id for noninteractive"), myAuthKey, protocol, myShard, ppm); err != nil {
		return nil, errs.WrapArgument(err, "could not validate input")
	}
	signingParticipant := signing.NewParticipant(myAuthKey, nil, protocol, nil, nil, ppm.PreSigners, myShard)
	participant := &Cosigner{
		Participant: signingParticipant,
		ppm:         ppm,
	}

	if err := types.ValidateThresholdSignatureProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a valid interactive dkls23 cosigner")
	}

	return participant, nil
}

func validateInputsSign(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdSignatureProtocol, shard *dkls23.Shard, ppm *dkls23.PreProcessingMaterial) error {
	if ppm == nil {
		return errs.NewIsNil("ppm")
	}
	if err := validateInputs(sessionId, authKey, protocol, shard, ppm.PreSigners); err != nil {
		return err
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if err := ppm.Validate(authKey, protocol); err != nil {
		return errs.WrapValidation(err, "preprocessing material")
	}
	return nil
}
