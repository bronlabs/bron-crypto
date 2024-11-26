package signing

import (
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_TBLS_BOLDYREVA-"

var _ types.ThresholdSignatureParticipant = (*Cosigner[bls12381.G1, bls12381.G2])(nil)
var _ types.ThresholdSignatureParticipant = (*Cosigner[bls12381.G2, bls12381.G1])(nil)

type Cosigner[K bls.KeySubGroup, S bls.SignatureSubGroup] struct {
	// Base participant
	myAuthKey  types.AuthKey
	Protocol   types.ThresholdSignatureProtocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	// Threshold participant
	mySharingId   types.SharingID
	sharingConfig types.SharingConfig

	signer *bls.Signer[K, S]

	myShard *boldyreva02.Shard[K]
	scheme  bls.RogueKeyPrevention
	quorum  ds.Set[types.IdentityKey]
}

func (p *Cosigner[_, _]) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Cosigner[_, _]) SharingId() types.SharingID {
	return p.mySharingId
}

func (p *Cosigner[_, _]) RogueKeyPreventionScheme() bls.RogueKeyPrevention {
	return p.scheme
}

func (p *Cosigner[_, _]) Quorum() ds.Set[types.IdentityKey] {
	return p.quorum
}

func NewCosigner[K bls.KeySubGroup, S bls.SignatureSubGroup](sessionId []byte, authKey types.AuthKey, scheme bls.RogueKeyPrevention, quorum ds.Set[types.IdentityKey], myShard *boldyreva02.Shard[K], protocol types.ThresholdSignatureProtocol, transcript transcripts.Transcript) (*Cosigner[K, S], error) {
	if err := validateInputs[K, S](sessionId, authKey, quorum, myShard, protocol); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct the cossigner")
	}

	dst := fmt.Sprintf("%s-%s-%d", transcriptLabel, protocol.Curve().Name(), scheme)
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, nil)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(authKey)
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
		Protocol:      protocol,
		myAuthKey:     authKey,
		SessionId:     boundSessionId,
		sharingConfig: sharingConfig,
		mySharingId:   mySharingId,
		myShard:       myShard,
		Transcript:    transcript,
		scheme:        scheme,
		quorum:        quorum,
		Round:         1,
	}

	if err := types.ValidateThresholdSignatureProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct boldyreva02 interactive cosigner")
	}

	return participant, nil
}

func validateInputs[K bls.KeySubGroup, S bls.SignatureSubGroup](sessionId []byte, myAuthKey types.AuthKey, quorum ds.Set[types.IdentityKey], shard *boldyreva02.Shard[K], protocol types.ThresholdSignatureProtocol) error {
	if bls.SameSubGroup[K, S]() {
		return errs.NewType("key subgroup and signature subgroup can't be the same")
	}
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := types.ValidateAuthKey(myAuthKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if protocol.Curve().Name() != bls12381.GetSourceSubGroup[K]().Name() {
		return errs.NewArgument("protocol config curve mismatch with the declared subgroup")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "shard")
	}
	if quorum == nil {
		return errs.NewIsNil("session participants")
	}
	if quorum.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants")
	}
	if !quorum.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("session participant is not a subset of the protocol")
	}
	return nil
}
