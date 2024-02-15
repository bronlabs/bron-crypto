package signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var _ types.ThresholdSignatureParticipant = (*Cosigner)(nil)

type Cosigner struct {
	signer   *bls.Signer[bls12381.G1, bls12381.G2]
	protocol types.ThresholdSignatureProtocol

	myAuthKey     types.AuthKey
	mySharingId   types.SharingID
	myShard       *glow.Shard
	sharingConfig types.SharingConfig

	sid        []byte
	prng       io.Reader
	transcript transcripts.Transcript
	round      int
}

func (p *Cosigner) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Cosigner) SharingId() types.SharingID {
	return p.mySharingId
}

func NewCosigner(sid []byte, myAuthKey types.AuthKey, sessionParticipants ds.HashSet[types.IdentityKey], myShard *glow.Shard, protocol types.ThresholdSignatureProtocol, transcript transcripts.Transcript, prng io.Reader) (*Cosigner, error) {
	if err := validateInputs(sid, myAuthKey, sessionParticipants, myShard, protocol, prng); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct the cossigner")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(glow.TranscriptLabel, nil)
	}
	transcript.AppendMessages("threshold bls signing", sid)

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.LookUpRight(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	signingKeyShareAsPrivateKey, err := bls.NewPrivateKey[bls12381.G1](myShard.SigningKeyShare.Share)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consider my signing key share as a bls private key")
	}
	signer, err := bls.NewSigner[bls12381.G1, bls12381.G2](signingKeyShareAsPrivateKey, bls.Basic)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't construct bls cosigner")
	}

	cosigner := &Cosigner{
		signer:        signer,
		protocol:      protocol,
		myAuthKey:     myAuthKey,
		sid:           sid,
		sharingConfig: sharingConfig,
		mySharingId:   mySharingId,
		transcript:    transcript,
		myShard:       myShard,
		prng:          prng,
		round:         1,
	}

	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct glow interactive cosigner")
	}

	return cosigner, nil
}

func validateInputs(sid []byte, myAuthKey types.AuthKey, sessionParticipants ds.HashSet[types.IdentityKey], shard *glow.Shard, protocol types.ThresholdSignatureProtocol, prng io.Reader) error {
	if len(sid) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := types.ValidateAuthKey(myAuthKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if protocol.Curve().Name() != new(glow.KeySubGroup).Name() {
		return errs.NewArgument("cohort config curve mismatch with the declared subgroup")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "shard")
	}
	if sessionParticipants == nil {
		return errs.NewIsNil("session participants")
	}
	if sessionParticipants.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants")
	}
	if !sessionParticipants.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("session participant is not a subset of the protocol")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}
