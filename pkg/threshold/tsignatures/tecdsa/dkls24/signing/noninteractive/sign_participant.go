package noninteractiveSigning

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

var _ signing.Participant = (*Cosigner)(nil)

type Cosigner struct {
	myAuthKey     types.AuthKey
	mySharingId   types.SharingID
	myShard       *dkls24.Shard
	protocol      types.ThresholdSignatureProtocol
	sharingConfig types.SharingConfig
	ppm           *dkls24.PreProcessingMaterial
}

func (c *Cosigner) Shard() *dkls24.Shard {
	return c.myShard
}

func (c *Cosigner) Protocol() types.ThresholdSignatureProtocol {
	return c.protocol
}

func (c *Cosigner) SharingConfig() types.SharingConfig {
	return c.sharingConfig
}

func (*Cosigner) Prng() io.Reader {
	return nil
}

func (*Cosigner) SessionId() []byte {
	return nil
}

func (c *Cosigner) IdentityKey() types.IdentityKey {
	return c.myAuthKey
}

func (c *Cosigner) AuthKey() types.AuthKey {
	return c.myAuthKey
}

func (c *Cosigner) SharingId() types.SharingID {
	return c.mySharingId
}

func (c *Cosigner) IsSignatureAggregator() bool {
	return c.Protocol().Participants().Contains(c.IdentityKey())
}

func NewCosigner(myAuthKey types.AuthKey, myShard *dkls24.Shard, protocol types.ThresholdSignatureProtocol, ppm *dkls24.PreProcessingMaterial) (cosigner *Cosigner, err error) {
	if err := validateInputsSign([]byte("no session id for noninteractive"), myAuthKey, protocol, myShard, ppm); err != nil {
		return nil, errs.WrapArgument(err, "could not validate input")
	}
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.LookUpRight(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	participant := &Cosigner{
		myAuthKey:     myAuthKey,
		mySharingId:   mySharingId,
		myShard:       myShard,
		protocol:      protocol,
		sharingConfig: sharingConfig,
		ppm:           ppm,
	}

	if err := types.ValidateThresholdSignatureProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a valid interactive dkls24 cosigner")
	}

	return participant, nil
}

func validateInputsSign(uniqueSessionId []byte, authKey types.AuthKey, protocol types.ThresholdSignatureProtocol, shard *dkls24.Shard, ppm *dkls24.PreProcessingMaterial) error {
	if ppm == nil {
		return errs.NewIsNil("ppm")
	}
	if err := validateInputs(uniqueSessionId, authKey, protocol, shard, ppm.PreSigners); err != nil {
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
