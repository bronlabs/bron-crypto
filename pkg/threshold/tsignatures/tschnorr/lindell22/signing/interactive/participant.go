package interactive_signing

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel = "COPPER_KRYPTON_LINDELL22_SIGN-"
)

type state struct {
	pid         []byte
	bigS        []byte
	k           curves.Scalar
	bigR        curves.Point
	bigRWitness commitments.Witness

	theirBigRCommitment ds.Map[types.IdentityKey, commitments.Commitment]

	_ ds.Incomparable
}

type Cosigner[F schnorr.Variant[F]] struct {
	przsParticipant *setup.Participant

	myAuthKey         types.AuthKey
	mySharingId       types.SharingID
	mySigningKeyShare *tsignatures.SigningKeyShare

	variant       schnorr.Variant[F]
	protocol      types.ThresholdSignatureProtocol
	quorum        ds.Set[types.IdentityKey]
	sharingConfig types.SharingConfig
	sessionId     []byte
	round         int
	transcript    transcripts.Transcript
	nic           compiler.Name
	prng          io.Reader

	state *state

	_ ds.Incomparable
}

var _ types.ThresholdSignatureParticipant = (*Cosigner[schnorr.EdDsaCompatibleVariant])(nil)

func (p *Cosigner[F]) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Cosigner[F]) SharingId() types.SharingID {
	return p.mySharingId
}

func NewCosigner[F schnorr.Variant[F]](myAuthKey types.AuthKey, sessionId []byte, quorum ds.Set[types.IdentityKey], myShard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, variant schnorr.Variant[F], prng io.Reader) (p *Cosigner[F], err error) {
	if err := validateInputs(sessionId, myAuthKey, quorum, myShard, protocol, niCompiler, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	transcript, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	pid := myAuthKey.PublicKey().ToAffineCompressed()
	bigS := signing.BigS(quorum)
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("couldn't find my sharign id")
	}

	przsProtocol, err := types.NewMPCProtocol(protocol.Curve(), quorum)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't configure przs")
	}
	przsParticipant, err := setup.NewParticipant(sessionId, myAuthKey, przsProtocol, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot initialise PRZS participant")
	}

	cosigner := &Cosigner[F]{
		przsParticipant:   przsParticipant,
		myAuthKey:         myAuthKey,
		mySharingId:       mySharingId,
		mySigningKeyShare: myShard.SigningKeyShare,
		sharingConfig:     sharingConfig,
		protocol:          protocol,
		sessionId:         sessionId,
		transcript:        transcript,
		quorum:            quorum,
		variant:           variant,
		round:             1,
		prng:              prng,
		nic:               niCompiler,
		state: &state{
			pid:  pid,
			bigS: bigS,
		},
	}

	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct lindell22 cosigner")
	}
	return cosigner, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, quorum ds.Set[types.IdentityKey], shard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, nic compiler.Name, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
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
	if !compilerUtils.CompilerIsSupported(nic) {
		return errs.NewType("compile is not supported: %s", nic)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
