package noninteractive_signing

// import (
// 	"io"

// 	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/types"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/types"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
// 	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
// 	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
// ).

// var _ types.PreSignedThresholdSignatureParticipant = (*Cosigner)(nil).

// type Cosigner struct {
// 	lindell17.Participant

// 	myAuthKey           types.AuthKey
// 	mySharingId         int
// 	myShard             *lindell17.Shard
// 	myPreSignatureBatch *lindell17.PreSignatureBatch

// 	theirIdentityKey types.IdentityKey
// 	theirSharingId   int

// 	preSignatureIndex int
// 	protocol          types.PreSignedThresholdSignatureProtocol
// 	prng              io.Reader

// 	_ ds.Incomparable
// }.

// func (p *Cosigner) IdentityKey() types.IdentityKey {
// 	return p.myAuthKey
// }.

// func (p *Cosigner) AuthKey() types.AuthKey {
// 	return p.myAuthKey
// }.

// func (p *Cosigner) SharingId() int {
// 	return p.mySharingId
// }.

// func (p *Cosigner) IsSignatureAggregator() bool {
// 	return p.protocol.SignatureAggregators().Contains(p.IdentityKey())
// }.

// func (p *Cosigner) IsPreSignatureComposer() bool {
// 	return types.Equals(p.protocol.PreSignatureComposer(), p.IdentityKey())
// }.

// func NewCosigner(sessionId []byte, protocol types.PreSignedThresholdSignatureProtocol, myAuthKey types.AuthKey, myShard *lindell17.Shard, myPreSignatureBatch *lindell17.PreSignatureBatch, preSignatureIndex int, aggregatorIdentity types.IdentityKey, transcript transcripts.Transcript, prng io.Reader) (participant *Cosigner, err error) {
// 	err = validateCosignerInputs(sessionId, protocol, myAuthKey, myShard, myPreSignatureBatch, preSignatureIndex, aggregatorIdentity, prng)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to validate inputs")
// 	}

// 	_, keyToId, mySharingId := types.DeriveSharingIds(myAuthKey, protocol.Participants())
// 	theirSharingId := keyToId[aggregatorIdentity.Hash()]

// dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
// transcript, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
// if err != nil {
// 	return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
// }.

// 	participant = &Cosigner{
// 		myAuthKey:           myAuthKey,
// 		mySharingId:         mySharingId,
// 		myShard:             myShard,
// 		myPreSignatureBatch: myPreSignatureBatch,
// 		theirIdentityKey:    aggregatorIdentity,
// 		theirSharingId:      theirSharingId,
// 		preSignatureIndex:   preSignatureIndex,
// 		protocol:            protocol,
// 		prng:                prng,
// 	}

// 	if err := types.ValidatePreSignedThresholdSignatureProtocol(participant, protocol); err != nil {
// 		return nil, errs.WrapVerificationFailed(err, "couldn't construct non interactive cosigner")
// 	}
// 	return participant, nil
// }.

// func validateCosignerInputs(sessionId []byte, protocol types.PreSignedThresholdSignatureProtocol, myAuthKey types.AuthKey, myShard *lindell17.Shard, myPreSignatureBatch *lindell17.PreSignatureBatch, preSignatureIndex int, other types.IdentityKey, prng io.Reader) error {
// 	if len(sessionId) == 0 {
// 		return errs.NewArgument("invalid session id: %s", sessionId)
// 	}
// 	if err := types.ValidatePreSignedThresholdSignatureProtocolConfig(protocol); err != nil {
// 		return errs.WrapVerificationFailed(err, "presigned threshold signature protocol config")
// 	}
// 	if err := types.ValidateAuthKey(myAuthKey); err != nil {
// 		return errs.WrapVerificationFailed(err, "auth key")
// 	}
// 	if err := myShard.Validate(protocol, myAuthKey, false); err != nil {
// 		return errs.WrapVerificationFailed(err, "my shard")
// 	}
// 	if err := myPreSignatureBatch.Validate(protocol); err != nil {
// 		return errs.WrapVerificationFailed(err, "pre signature batch")
// 	}
// 	if preSignatureIndex >= len(myPreSignatureBatch.PreSignatures) {
// 		return errs.NewArgument("presignature index %d is invalid", preSignatureIndex)
// 	}
// 	if err := types.ValidateIdentityKey(other); err != nil {
// 		return errs.WrapVerificationFailed(err, "other party identity key")
// 	}
// 	if !protocol.Participants().Contains(other) {
// 		return errs.NewMembership("secondary is not a participant")
// 	}
// 	if types.Equals(myAuthKey, other) {
// 		return errs.NewArgument("other and me are the same")
// 	}
// 	if prng == nil {
// 		return errs.NewIsNil("prng is nil")
// 	}
// 	return nil
// }.
