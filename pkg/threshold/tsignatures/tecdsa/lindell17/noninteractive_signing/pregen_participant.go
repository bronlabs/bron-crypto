package noninteractive_signing

// import (
// 	"io"

// 	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/types"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/types"
// 	"github.com/copperexchange/krypton-primitives/pkg/commitments"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
// 	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
// 	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
// ).

// var _ types.PreSignedThresholdSignatureParticipant = (*PreGenParticipant)(nil).

// type preGenParticipantState struct {
// 	k           []curves.Scalar
// 	bigR        []curves.Point
// 	bigRWitness []commitments.Witness

// 	theirBigRCommitments []map[types.IdentityHash]commitments.Commitment

// 	_ ds.Incomparable
// }.

// type PreGenParticipant struct {
// 	lindell17.Participant

// 	myAuthKey   types.AuthKey
// 	mySharingId int
// 	tau         int
// 	protocol    types.PreSignedThresholdSignatureProtocol
// 	sid         []byte
// 	transcript  transcripts.Transcript
// 	round       int
// 	prng        io.Reader

// 	state *preGenParticipantState

// 	_ ds.Incomparable
// }.

// func (p *PreGenParticipant) IdentityKey() types.IdentityKey {
// 	return p.myAuthKey
// }.

// func (p *PreGenParticipant) AuthKey() types.AuthKey {
// 	return p.myAuthKey
// }.

// func (p *PreGenParticipant) SharingId() int {
// 	return p.mySharingId
// }.

// func (p *PreGenParticipant) IsSignatureAggregator() bool {
// 	return p.protocol.SignatureAggregators().Contains(p.IdentityKey())
// }.

// func (p *PreGenParticipant) IsPreSignatureComposer() bool {
// 	return types.Equals(p.protocol.PreSignatureComposer(), p.IdentityKey())
// }.

// const (
// 	transcriptAppLabel       = "Lindell2017_PreGen"
// 	transcriptSessionIdLabel = "Lindell2017_PreGen_SessionId"
// ).

// func NewPreGenParticipant(sid []byte, transcript transcripts.Transcript, myAuthKey types.AuthKey, protocol types.PreSignedThresholdSignatureProtocol, tau int, prng io.Reader) (participant *PreGenParticipant, err error) {
// 	err = validateInputs(sid, myAuthKey, protocol, tau, prng)
// 	if err != nil {
// 		return nil, errs.WrapArgument(err, "failed to validate inputs")
// 	}

// 	if transcript == nil {
// 		transcript = hagrid.NewTranscript(transcriptAppLabel, nil)
// 	}
// 	transcript.AppendMessages(transcriptSessionIdLabel, sid)

// 	participant = &PreGenParticipant{
// 		myAuthKey:  myAuthKey,
// 		protocol:   protocol,
// 		tau:        tau,
// 		prng:       prng,
// 		sid:        sid,
// 		transcript: transcript,
// 		round:      1,
// 		state:      &preGenParticipantState{},
// 	}
// 	if err := types.ValidatePreSignedThresholdSignatureProtocol(participant, protocol); err != nil {
// 		return nil, errs.WrapVerificationFailed(err, "could not construct pregen participant")
// 	}
// 	return participant, nil
// }.

// func validateInputs(sessionId []byte, myAuthKey types.AuthKey, protocol types.PreSignedThresholdSignatureProtocol, tau int, prng io.Reader) error {.

// 	if len(sessionId) == 0 {
// 		return errs.NewArgument("invalid session id: %s", sessionId)
// 	}
// 	if err := types.ValidatePreSignedThresholdSignatureProtocolConfig(protocol); err != nil {
// 		return errs.WrapVerificationFailed(err, "presigned threshold signature protocol config")
// 	}
// 	if err := types.ValidateAuthKey(myAuthKey); err != nil {
// 		return errs.WrapVerificationFailed(err, "auth key")
// 	}
// 	if tau <= 0 {
// 		return errs.NewArgument("tau is non-positive")
// 	}
// 	if prng == nil {
// 		return errs.NewIsNil("prng is nil")
// 	}
// 	return nil
// }.
