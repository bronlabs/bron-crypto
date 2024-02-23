package noninteractive_signing

import (
	"fmt"
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel = "COPPER_KRYPTON_LINDELL22_PREGEN-"
)

var _ types.ThresholdParticipant = (*PreGenParticipant)(nil)

type PreGenParticipant struct {
	przsSetupParticipant *setup.Participant
	nic                  compiler.Name

	myAuthKey   types.AuthKey
	mySharingId types.SharingID

	protocol   types.ThresholdProtocol
	preSigners ds.HashSet[types.IdentityKey]
	sessionId  []byte
	round      int
	prng       io.Reader
	transcript transcripts.Transcript

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
	bigRWitness         commitments.Witness
	theirBigRCommitment ds.HashMap[types.IdentityKey, commitments.Commitment]

	_ ds.Incomparable
}

func NewPreGenParticipant(myAuthKey types.AuthKey, sessionId []byte, protocol types.ThresholdProtocol, preSigners ds.HashSet[types.IdentityKey], nic compiler.Name, transcript transcripts.Transcript, prng io.Reader) (participant *PreGenParticipant, err error) {
	if err := validatePreGenInputs(myAuthKey, sessionId, protocol, preSigners, nic, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid argument")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), nic)
	transcript, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	// TODO: remove pid after adding Repr method to Identity Key
	pid := myAuthKey.PublicKey().ToAffineCompressed()
	bigS := signing.BigS(preSigners)
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.LookUpRight(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	przsSid := slices.Concat(sessionId, []byte("przs"))
	przsParticipant, err := setup.NewParticipant(przsSid, myAuthKey, protocol, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create PRZS setup participant")
	}

	participant = &PreGenParticipant{
		nic:                  nic,
		przsSetupParticipant: przsParticipant,
		preSigners:           preSigners,
		myAuthKey:            myAuthKey,
		mySharingId:          mySharingId,
		protocol:             protocol,
		sessionId:            sessionId,
		transcript:           transcript,
		round:                1,
		prng:                 prng,
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

func validatePreGenInputs(authKey types.AuthKey, sessionId []byte, protocol types.ThresholdProtocol, preSigners ds.HashSet[types.IdentityKey], nic compiler.Name, prng io.Reader) error {
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
	return nil
}
