package signing

// import (
// 	"fmt"
// 	"io"

// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves"
// 	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/base/types"
// 	hashcommitments "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
// 	"github.com/bronlabs/bron-crypto/pkg/network"
// 	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
// 	compilerUtils "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler_utils"
// 	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
// 	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
// 	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17"
// 	"github.com/bronlabs/bron-crypto/pkg/transcripts"
// 	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
// )

// const (
// 	transcriptLabel = "BRON_CRYPTO_LINDELL17_SIGN-"
// )

// type Cosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
// 	round uint
// 	// Base participant
// 	prng  io.Reader
// 	curve ecdsa.Curve[P, B, S]
// 	sid   network.SID
// 	tape  transcripts.Transcript

// 	// Threshold participant
// 	shard       *lindell17.Shard[P, B, S]
// 	nic         compiler.Name
// 	quorumBytes network.Quorum
// }

// type PrimaryCosignerState[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
// 	k1           S
// 	bigR1Opening hashcommitments.Witness
// 	bigR         P
// 	r            S
// 	bigR1        P
// }

// type PrimaryCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
// 	Cosigner[P, B, S]

// 	secondarySharingId sharing.ID
// 	state              *PrimaryCosignerState[P, B, S]
// }

// type SecondaryCosignerState[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
// 	bigR1Commitment hashcommitments.Commitment
// 	k2              S
// 	bigR2           P
// }

// type SecondaryCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
// 	Cosigner[P, B, S]

// 	primarySharingId sharing.ID
// 	state            *SecondaryCosignerState[P, B, S]
// }

// func (cosigner *Cosigner[P, B, S]) SharingID() sharing.ID {
// 	return cosigner.shard.Share().ID()
// }

// func newCosigner(sessionId []byte, myAuthKey types.AuthKey, hisIdentityKey types.IdentityKey, myShard *lindell17.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader, roundNo int) (cosigner *Cosigner, hisSharingId types.SharingID, err error) {
// 	err = validateInputs(sessionId, myAuthKey, hisIdentityKey, myShard, protocol, niCompiler, prng)
// 	if err != nil {
// 		return nil, 0, errs.WrapArgument(err, "invalid input arguments")
// 	}

// 	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), niCompiler)
// 	if transcript == nil {
// 		transcript = hagrid.NewTranscript(dst, prng)
// 	}
// 	boundSessionId, err := transcript.Bind(sessionId, dst)
// 	if err != nil {
// 		return nil, 0, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
// 	}

// 	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
// 	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
// 	if !exists {
// 		return nil, 0, errs.NewMissing("could not find my sharing id")
// 	}
// 	hisSharingId, exists = sharingConfig.Reverse().Get(hisIdentityKey)
// 	if !exists {
// 		return nil, 0, errs.NewMissing("could not find the other party sharing id")
// 	}
// 	return &Cosigner{
// 		myAuthKey:   myAuthKey,
// 		Prng:        prng,
// 		Protocol:    protocol,
// 		Round:       roundNo,
// 		SessionId:   boundSessionId,
// 		Transcript:  transcript,
// 		mySharingId: mySharingId,
// 		myShard:     myShard,
// 		nic:         niCompiler,
// 	}, hisSharingId, nil
// }

// func NewPrimaryCosigner(sessionId []byte, myAuthKey types.AuthKey, secondaryIdentityKey types.IdentityKey, myShard *lindell17.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (primaryCosigner *PrimaryCosigner, err error) {
// 	cosigner, hisSharingId, err := newCosigner(sessionId, myAuthKey, secondaryIdentityKey, myShard, protocol, niCompiler, transcript, prng, 1)
// 	if err != nil {
// 		return nil, errs.WrapValidation(err, "could not construct primary cosigner")
// 	}
// 	primaryCosigner = &PrimaryCosigner{
// 		Cosigner:             *cosigner,
// 		secondaryIdentityKey: secondaryIdentityKey,
// 		secondarySharingId:   hisSharingId,
// 		state:                &PrimaryCosignerState{},
// 	}
// 	primaryCosigner.quorum = hashset.NewHashableHashSet[types.IdentityKey](myAuthKey, secondaryIdentityKey)
// 	if err := types.ValidateThresholdSignatureProtocol(primaryCosigner, protocol); err != nil {
// 		return nil, errs.WrapValidation(err, "could not validate primary cosigner")
// 	}
// 	return primaryCosigner, nil
// }

// func NewSecondaryCosigner(sessionId []byte, myAuthKey types.AuthKey, primaryIdentityKey types.IdentityKey, myShard *lindell17.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (secondaryCosigner *SecondaryCosigner, err error) {
// 	cosigner, hisSharingId, err := newCosigner(sessionId, myAuthKey, primaryIdentityKey, myShard, protocol, niCompiler, transcript, prng, 2)
// 	if err != nil {
// 		return nil, errs.WrapValidation(err, "could not construct secondary cosigner")
// 	}
// 	secondaryCosigner = &SecondaryCosigner{
// 		Cosigner:           *cosigner,
// 		primaryIdentityKey: primaryIdentityKey,
// 		primarySharingId:   hisSharingId,
// 		state:              &SecondaryCosignerState{},
// 	}
// 	secondaryCosigner.quorum = hashset.NewHashableHashSet[types.IdentityKey](myAuthKey, primaryIdentityKey)
// 	if err := types.ValidateThresholdSignatureProtocol(secondaryCosigner, protocol); err != nil {
// 		return nil, errs.WrapValidation(err, "could not validate secondary cosigner")
// 	}
// 	return secondaryCosigner, nil
// }

// func validateInputs(sessionId []byte, myAuthKey types.AuthKey, other types.IdentityKey, myShard *lindell17.Shard, protocol types.ThresholdSignatureProtocol, nic compiler.Name, prng io.Reader) error {
// 	if len(sessionId) == 0 {
// 		return errs.NewArgument("invalid session id: %s", sessionId)
// 	}
// 	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
// 		return errs.WrapValidation(err, "threshold signature protocol config")
// 	}
// 	if err := types.ValidateAuthKey(myAuthKey); err != nil {
// 		return errs.WrapValidation(err, "auth key")
// 	}
// 	if err := types.ValidateIdentityKey(other); err != nil {
// 		return errs.WrapValidation(err, "secondary identity key")
// 	}
// 	if err := myShard.Validate(protocol, myAuthKey, true); err != nil {
// 		return errs.WrapValidation(err, "my shard")
// 	}
// 	if !protocol.Participants().Contains(other) {
// 		return errs.NewMembership("secondary is not a participant")
// 	}
// 	if other.Equal(myAuthKey) {
// 		return errs.NewArgument("other and me are the same")
// 	}
// 	if !compilerUtils.CompilerIsSupported(nic) {
// 		return errs.NewType("compiler is not supported %s", nic)
// 	}
// 	if prng == nil {
// 		return errs.NewIsNil("prng is nil")
// 	}
// 	return nil
// }
