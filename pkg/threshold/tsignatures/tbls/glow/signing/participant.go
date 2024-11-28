package signing

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_THRESHOLD_BLS_GLOW-"

var _ types.ThresholdSignatureParticipant = (*Cosigner)(nil)

type Cosigner struct {
	signer   *bls.Signer[bls12381.G1, bls12381.G2]
	protocol types.ThresholdSignatureProtocol

	myAuthKey     types.AuthKey
	mySharingId   types.SharingID
	myShard       *glow.Shard
	sharingConfig types.SharingConfig

	sessionId  []byte
	prng       io.Reader
	transcript transcripts.Transcript
	round      int
	quorum     ds.Set[types.IdentityKey]

	_ ds.Incomparable
}

func (p *Cosigner) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Cosigner) SharingId() types.SharingID {
	return p.mySharingId
}

func (p *Cosigner) Quorum() ds.Set[types.IdentityKey] {
	return p.quorum
}

func NewCosigner(sessionId []byte, myAuthKey types.AuthKey, quorum ds.Set[types.IdentityKey], myShard *glow.Shard, protocol types.ThresholdSignatureProtocol, transcript transcripts.Transcript, prng io.Reader) (*Cosigner, error) {
	if err := validateInputs(sessionId, myAuthKey, quorum, myShard, protocol, prng); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct the cossigner")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, nil)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
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
		sessionId:     boundSessionId,
		sharingConfig: sharingConfig,
		mySharingId:   mySharingId,
		transcript:    transcript,
		myShard:       myShard,
		prng:          prng,
		quorum:        quorum,
		round:         1,
	}

	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct glow interactive cosigner")
	}

	return cosigner, nil
}

func validateInputs(sessionId []byte, myAuthKey types.AuthKey, quorum ds.Set[types.IdentityKey], shard *glow.Shard, protocol types.ThresholdSignatureProtocol, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := types.ValidateAuthKey(myAuthKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if protocol.Curve().Name() != new(glow.KeySubGroup).Name() {
		return errs.NewArgument("protocol config curve mismatch with the declared subgroup")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "shard")
	}
	if quorum == nil {
		return errs.NewIsNil("session participants")
	}
	if quorum.Size() < safecast.ToInt(protocol.Threshold()) {
		return errs.NewSize("not enough session participants")
	}
	if !quorum.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("session participant is not a subset of the protocol")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}
