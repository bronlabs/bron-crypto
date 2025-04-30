package interactive_signing

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
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const (
	transcriptLabel = "BRON_CRYPTO_LINDELL22_SIGN-"
)

type state struct {
	pid     []byte
	bigS    []byte
	k       curves.Scalar
	bigR    curves.Point
	opening hashcommitments.Witness

	theirBigRCommitment ds.Map[types.IdentityKey, hashcommitments.Commitment]

	_ ds.Incomparable
}

type Cosigner[F schnorr.Variant[F, M], M any] struct {
	// Base participant
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.ThresholdSignatureProtocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	// Threshold participant
	mySharingId   types.SharingID
	sharingConfig types.SharingConfig

	mySigningKeyShare *tsignatures.SigningKeyShare

	variant schnorr.Variant[F, M]
	quorum  ds.Set[types.IdentityKey]
	nic     compiler.Name

	state *state

	_ ds.Incomparable
}

func (p *Cosigner[V, M]) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Cosigner[V, M]) SharingId() types.SharingID {
	return p.mySharingId
}

func (p *Cosigner[V, M]) Variant() schnorr.Variant[V, M] {
	return p.variant
}

func (p *Cosigner[V, M]) Quorum() ds.Set[types.IdentityKey] {
	return p.quorum
}

func NewCosigner[V schnorr.Variant[V, M], M any](myAuthKey types.AuthKey, sessionId []byte, quorum ds.Set[types.IdentityKey], myShard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, variant schnorr.Variant[V, M], prng io.Reader) (p *Cosigner[V, M], err error) {
	if err := validateInputs(sessionId, myAuthKey, quorum, myShard, protocol, niCompiler, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	pid := myAuthKey.PublicKey().ToAffineCompressed()
	bigS := signing.BigS(quorum)
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("couldn't find my sharing id")
	}

	cosigner := &Cosigner[V, M]{
		myAuthKey:         myAuthKey,
		Prng:              prng,
		Protocol:          protocol,
		Round:             1,
		SessionId:         boundSessionId,
		Transcript:        transcript,
		mySharingId:       mySharingId,
		sharingConfig:     sharingConfig,
		mySigningKeyShare: myShard.SigningKeyShare,
		quorum:            quorum,
		variant:           variant,
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
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), quorum.List()...) {
		return errs.NewCurve("presigners have different curves")
	}
	if !curveutils.AllOfSameCurve(protocol.Curve(), shard.SigningKeyShare.PublicKey, shard.SigningKeyShare.PublicKey) {
		return errs.NewCurve("shard and protocol have different curves")
	}
	return nil
}
