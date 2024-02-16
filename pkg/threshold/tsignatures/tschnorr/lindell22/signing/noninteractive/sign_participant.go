package noninteractive_signing

import (
	"bytes"
	"fmt"
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var _ types.ThresholdSignatureParticipant = (*Cosigner)(nil)

type Cosigner struct {
	przsSampleParticipant *sample.Participant

	myAuthKey   types.AuthKey
	mySharingId types.SharingID
	myShard     *lindell22.Shard
	ppm         *lindell22.PreProcessingMaterial

	taproot       bool
	sharingConfig types.SharingConfig
	protocol      types.ThresholdSignatureProtocol
	prng          io.Reader

	_ ds.Incomparable
}

func (c *Cosigner) IdentityKey() types.IdentityKey {
	return c.myAuthKey
}

func (c *Cosigner) SharingId() types.SharingID {
	return c.mySharingId
}

func NewCosigner(sessionId []byte, myAuthKey types.AuthKey, myShard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, ppm *lindell22.PreProcessingMaterial, taproot bool, transcript transcripts.Transcript, prng io.Reader) (cosigner *Cosigner, err error) {
	if err := validateCosignerInputs(sessionId, myAuthKey, myShard, protocol, ppm, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}

	dst := fmt.Sprintf("%s-%s-%d", transcriptLabel, protocol.Curve().Name(), utils.BoolTo[byte](taproot))
	_, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	przsSid := bytes.Join([][]byte{sessionId, ppm.PrivateMaterial.K1.Bytes()}, nil)
	przsPrngFactory, err := chacha.NewChachaPRNG(nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create PRNG factory")
	}
	przsParticipant, err := sample.NewParticipant(przsSid, myAuthKey, ppm.PrivateMaterial.Seeds, protocol, ppm.PreSigners, przsPrngFactory)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create PRZS sampler")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.LookUpRight(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	cosigner = &Cosigner{
		przsSampleParticipant: przsParticipant,
		myAuthKey:             myAuthKey,
		myShard:               myShard,
		taproot:               taproot,
		protocol:              protocol,
		prng:                  prng,
		mySharingId:           mySharingId,
		sharingConfig:         sharingConfig,
		ppm:                   ppm,
	}

	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct cnoninteractive cosigner")
	}

	return cosigner, nil
}

func validateCosignerInputs(sessionId []byte, authKey types.AuthKey, shard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, ppm *lindell22.PreProcessingMaterial, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "shard")
	}
	if err := ppm.Validate(authKey, protocol); err != nil {
		return errs.WrapValidation(err, "preprocessing material")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}
