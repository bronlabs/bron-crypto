package signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var _ types.ThresholdSignatureParticipant = (*Cosigner[bls12381.G1, bls12381.G2])(nil)
var _ types.ThresholdSignatureParticipant = (*Cosigner[bls12381.G2, bls12381.G1])(nil)

type Cosigner[K bls.KeySubGroup, S bls.SignatureSubGroup] struct {
	signer   *bls.Signer[K, S]
	protocol types.ThresholdSignatureProtocol

	myAuthKey     types.AuthKey
	mySharingId   types.SharingID
	myShard       *boldyreva02.Shard[K]
	sharingConfig types.SharingConfig
	scheme        bls.RogueKeyPrevention

	sid        []byte
	transcript transcripts.Transcript
	round      int
}

func (p *Cosigner[_, _]) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Cosigner[_, _]) SharingId() types.SharingID {
	return p.mySharingId
}

func (p *Cosigner[K, S]) IsSignatureAggregator() bool {
	return p.protocol.SignatureAggregators().Contains(p.IdentityKey())
}

func NewCosigner[K bls.KeySubGroup, S bls.SignatureSubGroup](sid []byte, authKey types.AuthKey, scheme bls.RogueKeyPrevention, sessionParticipants ds.HashSet[types.IdentityKey], myShard *boldyreva02.Shard[K], protocol types.ThresholdSignatureProtocol, transcript transcripts.Transcript) (*Cosigner[K, S], error) {
	if err := validateInputs[K, S](sid, authKey, sessionParticipants, myShard, protocol); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct the cossigner")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_THRESHOLD_BLS_BOLDYREVA-", nil)
	}
	transcript.AppendMessages("threshold bls signing", sid)

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.LookUpRight(authKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	signingKeyShareAsPrivateKey, err := bls.NewPrivateKey[K](myShard.SigningKeyShare.Share)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consider my signing key share as a bls private key")
	}
	signer, err := bls.NewSigner[K, S](signingKeyShareAsPrivateKey, bls.POP)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't construct bls cosigner")
	}

	participant := &Cosigner[K, S]{
		signer:        signer,
		protocol:      protocol,
		myAuthKey:     authKey,
		sid:           sid,
		sharingConfig: sharingConfig,
		mySharingId:   mySharingId,
		myShard:       myShard,
		transcript:    transcript,
		scheme:        scheme,
		round:         1,
	}

	if err := types.ValidateThresholdSignatureProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct boldyreva02 interactive cosigner")
	}

	return participant, nil
}

func validateInputs[K bls.KeySubGroup, S bls.SignatureSubGroup](sid []byte, myAuthKey types.AuthKey, sessionParticipants ds.HashSet[types.IdentityKey], shard *boldyreva02.Shard[K], protocol types.ThresholdSignatureProtocol) error {
	if bls.SameSubGroup[K, S]() {
		return errs.NewType("key subgroup and signature subgroup can't be the same")
	}
	if len(sid) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := types.ValidateAuthKey(myAuthKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if protocol.Curve().Name() != bls12381.GetSourceSubGroup[K]().Name() {
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
	return nil
}
