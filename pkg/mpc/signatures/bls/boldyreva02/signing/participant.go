package signing

import (
	"encoding/hex"
	"fmt"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/bls/boldyreva02"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

const transcriptLabel = "BRON_CRYPTO_TBLS_BOLDYREVA-"

// Cosigner represents a participant in the Boldyreva BLS signing protocol.
// Each cosigner holds a shard of the secret key and can produce partial signatures
// that are later aggregated into a full signature.
type Cosigner[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	ctx               *session.Context
	shard             *boldyreva02.Shard[PK, PKFE, SG, SGFE, E, S]
	round             network.Round
	targetRogueKeyAlg bls.RogueKeyPreventionAlgorithm
	targetDst         string
	shareAsPrivateKey []*bls.PrivateKey[PK, PKFE, SG, SGFE, E, S]
	scheme            *bls.Scheme[PK, PKFE, SG, SGFE, E, S]
}

// SharingID returns the sharing identifier for this cosigner's share.
func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) SharingID() sharing.ID {
	if c == nil {
		return 0
	}
	return c.shard.Share().ID()
}

// Quorum returns the set of parties participating in this signing session.
// Returns nil if the receiver is nil.
func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) Quorum() network.Quorum {
	if c == nil {
		return nil
	}
	return c.ctx.Quorum()
}

// Shard returns the cosigner's secret shard used for producing partial signatures.
// Returns nil if the receiver is nil.
func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) Shard() *boldyreva02.Shard[PK, PKFE, SG, SGFE, E, S] {
	if c == nil {
		return nil
	}
	return c.shard
}

// Variant returns the BLS variant (short key or long key) used by this cosigner.
func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) Variant() bls.Variant {
	if c == nil {
		return 0
	}
	return c.scheme.Variant()
}

// TargetRogueKeyPreventionAlgorithm returns the rogue key prevention algorithm
// (Basic, MessageAugmentation, or POP) used by this cosigner.
func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) TargetRogueKeyPreventionAlgorithm() bls.RogueKeyPreventionAlgorithm {
	if c == nil {
		return 0
	}
	return c.targetRogueKeyAlg
}

// NewShortKeyCosigner creates a new Cosigner for the short key variant of BLS signatures.
// In this variant, public keys are in G1 (smaller) and signatures are in G2 (larger).
func NewShortKeyCosigner[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	ctx *session.Context,
	curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S],
	shard *boldyreva02.Shard[P1, FE1, P2, FE2, E, S],
	rogueKeyAlg bls.RogueKeyPreventionAlgorithm,
) (*Cosigner[P1, FE1, P2, FE2, E, S], error) {
	if curveFamily == nil {
		return nil, ErrInvalidArgument.WithMessage("curveFamily is nil")
	}
	scheme, err := bls.NewShortKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS scheme")
	}
	return newCosigner(ctx, curveFamily.Name(), curveFamily.SourceSubGroup(), shard, rogueKeyAlg, scheme, bls.ShortKey)
}

// NewLongKeyCosigner creates a new Cosigner for the long key variant of BLS signatures.
// In this variant, public keys are in G2 (larger) and signatures are in G1 (smaller).
func NewLongKeyCosigner[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	ctx *session.Context,
	curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S],
	shard *boldyreva02.Shard[P2, FE2, P1, FE1, E, S],
	rogueKeyAlg bls.RogueKeyPreventionAlgorithm,
) (*Cosigner[P2, FE2, P1, FE1, E, S], error) {
	if curveFamily == nil {
		return nil, ErrInvalidArgument.WithMessage("curveFamily is nil")
	}
	scheme, err := bls.NewLongKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS scheme")
	}
	return newCosigner(ctx, curveFamily.Name(), curveFamily.TwistedSubGroup(), shard, rogueKeyAlg, scheme, bls.LongKey)
}

func newCosigner[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	ctx *session.Context,
	curveFamilyName string,
	keySubGroup curves.PairingFriendlyCurve[PK, PKFE, SG, SGFE, E, S],
	shard *boldyreva02.Shard[PK, PKFE, SG, SGFE, E, S],
	rogueKeyAlg bls.RogueKeyPreventionAlgorithm,
	scheme *bls.Scheme[PK, PKFE, SG, SGFE, E, S],
	variant bls.Variant,
) (*Cosigner[PK, PKFE, SG, SGFE, E, S], error) {
	if ctx == nil {
		return nil, ErrInvalidArgument.WithMessage("ctx is nil")
	}
	if shard == nil {
		return nil, ErrInvalidArgument.WithMessage("shard is nil")
	}
	if ctx.HolderID() != shard.Share().ID() {
		return nil, ErrInvalidArgument.WithMessage("shard does not belong to the holder")
	}
	if !ctx.Quorum().Contains(shard.Share().ID()) {
		return nil, ErrInvalidArgument.WithMessage("quorum doesn't cannot contain participant %d", shard.Share().ID())
	}
	if !shard.MSP().Accepts(ctx.Quorum().List()...) {
		return nil, ErrInvalidArgument.WithMessage("quorum is not authorized in the access structure")
	}
	if !bls.RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, ErrInvalidArgument.WithMessage("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s%s-%s-%d-%d", transcriptLabel, hex.EncodeToString(sid[:]), curveFamilyName, variant, rogueKeyAlg)
	ctx.Transcript().AppendDomainSeparator(dst)

	shareAsPrivateKey := make([]*bls.PrivateKey[PK, PKFE, SG, SGFE, E, S], len(shard.Share().Value()))
	for i, shareValue := range shard.Share().Value() {
		privKey, err := bls.NewPrivateKey(keySubGroup, shareValue)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create additive share as private key")
		}
		shareAsPrivateKey[i] = privKey
	}

	blsDst, err := scheme.CipherSuite().GetDst(rogueKeyAlg, variant)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to get BLS destination for rogue key prevention algorithm")
	}
	return &Cosigner[PK, PKFE, SG, SGFE, E, S]{
		ctx:               ctx,
		shard:             shard,
		scheme:            scheme,
		targetRogueKeyAlg: rogueKeyAlg,
		targetDst:         blsDst,
		shareAsPrivateKey: shareAsPrivateKey,
		round:             1,
	}, nil
}

// ProducePartialSignature generates a partial BLS signature on the given message.
// This method can only be called once per signing session (in round 1).
// The partial signature includes a proof-of-possession if using the POP algorithm.
// Returns an error if called in the wrong round or if signing fails.
func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) ProducePartialSignature(message []byte) (*boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S], error) {
	if c.round != 1 {
		return nil, ErrRound.WithMessage("ProducePartialSignature can only be called in round 1, current round: %d", c.round)
	}
	if len(message) == 0 {
		return nil, ErrInvalidArgument.WithMessage("message cannot be empty")
	}
	var err error
	var sigmaPopI []*bls.Signature[SG, SGFE, PK, PKFE, E, S]
	switch c.targetRogueKeyAlg {
	case bls.Basic:
	case bls.MessageAugmentation:
		message, err = bls.AugmentMessage(message, c.shard.PublicKey().Value())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to augment message")
		}
	case bls.POP:
		popMsg := c.shard.PublicKey().Bytes()
		popDst := c.scheme.CipherSuite().GetPopDst(c.Variant())
		sigmaPopI = make([]*bls.Signature[SG, SGFE, PK, PKFE, E, S], len(c.shareAsPrivateKey))
		for i := range sigmaPopI {
			popSigner, err := c.scheme.Signer(c.shareAsPrivateKey[i], bls.SignWithCustomDST[PK](popDst))
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to create signer for POP")
			}
			sigmaPopI[i], err = popSigner.Sign(popMsg)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to sign POP message")
			}
		}
	default:
		return nil, ErrInvalidArgument.WithMessage("unsupported rogue key prevention algorithm: %d", c.targetRogueKeyAlg)
	}
	sigmaI := make([]*bls.Signature[SG, SGFE, PK, PKFE, E, S], len(c.shareAsPrivateKey))
	for i := range sigmaI {
		signer, err := c.scheme.Signer(c.shareAsPrivateKey[i], bls.SignWithCustomDST[PK](c.targetDst))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create signer")
		}
		sigmaI[i], err = signer.Sign(message)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to sign message")
		}
	}
	c.round++
	return &boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S]{
		SigmaI:    sigmaI,
		SigmaPopI: sigmaPopI,
	}, nil
}
