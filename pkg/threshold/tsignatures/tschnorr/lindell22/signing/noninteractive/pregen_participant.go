package noninteractive_signing

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	hashcommitments "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler_utils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const (
	transcriptLabel = "KRYPTON_LINDELL22_PREGEN-"
)

var _ types.ThresholdParticipant = (*PreGenParticipant)(nil)

type PreGenParticipant struct {
	// Base participant
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.ThresholdProtocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	// Threshold participant
	mySharingId types.SharingID

	nic compiler.Name

	preSigners ds.Set[types.IdentityKey]

	state *state

	_ ds.Incomparable
}

func (p *PreGenParticipant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *PreGenParticipant) SharingId() types.SharingID {
	return p.mySharingId
}

type state struct {
	pid                 []byte
	bigS                []byte
	k1                  curves.Scalar
	k2                  curves.Scalar
	bigR1               curves.Point
	bigR2               curves.Point
	opening             hashcommitments.Witness
	theirBigRCommitment ds.Map[types.IdentityKey, hashcommitments.Commitment]

	_ ds.Incomparable
}

func NewPreGenParticipant(myAuthKey types.AuthKey, sessionId []byte, protocol types.ThresholdProtocol, preSigners ds.Set[types.IdentityKey], nic compiler.Name, transcript transcripts.Transcript, prng io.Reader) (participant *PreGenParticipant, err error) {
	if err := validatePreGenInputs(myAuthKey, sessionId, protocol, preSigners, nic, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid argument")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), nic)
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	// TODO: remove pid after adding Repr method to Identity Key
	pid := myAuthKey.PublicKey().ToAffineCompressed()
	bigS := signing.BigS(protocol.Participants())
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	participant = &PreGenParticipant{
		myAuthKey:   myAuthKey,
		Prng:        prng,
		Protocol:    protocol,
		Round:       1,
		SessionId:   boundSessionId,
		Transcript:  transcript,
		mySharingId: mySharingId,
		nic:         nic,
		preSigners:  preSigners,
		state: &state{
			pid:  pid,
			bigS: bigS,
		},
	}

	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a lindell22 pregen participant")
	}

	return participant, nil
}

func validatePreGenInputs(authKey types.AuthKey, sessionId []byte, protocol types.ThresholdProtocol, preSigners ds.Set[types.IdentityKey], nic compiler.Name, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if preSigners == nil {
		return errs.NewIsNil("preSigners")
	}
	if !preSigners.Contains(authKey) {
		return errs.NewMembership("i am not a presigner")
	}
	if !preSigners.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("presigners are not a subset of total participants")
	}
	if !compilerUtils.CompilerIsSupported(nic) {
		return errs.NewType("compiler %s is not supported", nic)
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), preSigners.List()...) {
		return errs.NewCurve("presigners have different curves")
	}
	return nil
}
