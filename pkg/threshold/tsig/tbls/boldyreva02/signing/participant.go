package signing

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls/boldyreva02"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const transcriptLabel = "BRON_CRYPTO_TBLS_BOLDYREVA-"

// Cosigner represents a participant in the Boldyreva threshold BLS signing protocol.
// Each cosigner holds a shard of the secret key and can produce partial signatures
// that are later aggregated into a full threshold signature.
type Cosigner[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	sid               network.SID
	shard             *boldyreva02.Shard[PK, PKFE, SG, SGFE, E, S]
	quorum            network.Quorum
	tape              ts.Transcript
	round             network.Round
	targetRogueKeyAlg bls.RogueKeyPreventionAlgorithm
	targetDst         string
	shareAsPrivateKey *bls.PrivateKey[PK, PKFE, SG, SGFE, E, S]
	scheme            *bls.Scheme[PK, PKFE, SG, SGFE, E, S]
}

// SharingID returns the sharing identifier for this cosigner's share.
func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) SharingID() sharing.ID {
	return c.shard.Share().ID()
}

// Quorum returns the set of parties participating in this signing session.
// Returns nil if the receiver is nil.
func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) Quorum() network.Quorum {
	if c == nil {
		return nil
	}
	return c.quorum
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
	return c.scheme.Variant()
}

// TargetRogueKeyPreventionAlgorithm returns the rogue key prevention algorithm
// (Basic, MessageAugmentation, or POP) used by this cosigner.
func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) TargetRogueKeyPreventionAlgorithm() bls.RogueKeyPreventionAlgorithm {
	return c.targetRogueKeyAlg
}

// NewShortKeyCosigner creates a new Cosigner for the short key variant of BLS signatures.
// In this variant, public keys are in G1 (smaller) and signatures are in G2 (larger).
//
// Parameters:
//   - sid: Unique session identifier
//   - curveFamily: The pairing-friendly curve family to use
//   - shard: The party's secret shard
//   - quorum: The set of parties participating in signing
//   - rogueKeyAlg: The rogue key prevention algorithm (Basic, MessageAugmentation, or POP)
//   - tape: The transcript for domain separation
//
// Returns an error if any parameter is invalid or the quorum is not authorized.
func NewShortKeyCosigner[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	sid network.SID,
	curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S],
	shard *boldyreva02.Shard[P1, FE1, P2, FE2, E, S],
	quorum network.Quorum,
	rogueKeyAlg bls.RogueKeyPreventionAlgorithm,
	tape ts.Transcript,
) (*Cosigner[P1, FE1, P2, FE2, E, S], error) {
	if curveFamily == nil {
		return nil, ErrInvalidArgument.WithMessage("curveFamily is nil")
	}
	if tape == nil {
		return nil, ErrInvalidArgument.WithMessage("transcript is nil")
	}
	if shard == nil {
		return nil, ErrInvalidArgument.WithMessage("shard is nil")
	}
	if quorum == nil {
		return nil, ErrInvalidArgument.WithMessage("quorum is nil")
	}
	if !bls.RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, ErrInvalidArgument.WithMessage("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	if !shard.AccessStructure().IsAuthorized(quorum.List()...) {
		return nil, ErrInvalidArgument.WithMessage("quorum is not authorized in the access structure")
	}
	dst := fmt.Sprintf("%s-%d-%s-%d-%d", transcriptLabel, sid, curveFamily.Name(), bls.ShortKey, rogueKeyAlg)
	tape.AppendDomainSeparator(dst)
	scheme, err := bls.NewShortKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create BLS short key scheme")
	}
	shareAsPrivateKey, err := shard.AsBLSPrivateKey()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to convert shard to BLS private key")
	}
	blsDst, err := scheme.CipherSuite().GetDst(rogueKeyAlg, bls.ShortKey)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to get BLS destination for rogue key prevention algorithm")
	}
	return &Cosigner[P1, FE1, P2, FE2, E, S]{
		sid:               sid,
		shard:             shard,
		quorum:            quorum,
		tape:              tape,
		scheme:            scheme,
		targetRogueKeyAlg: rogueKeyAlg,
		targetDst:         blsDst,
		shareAsPrivateKey: shareAsPrivateKey,
		round:             1,
	}, nil
}

// NewLongKeyCosigner creates a new Cosigner for the long key variant of BLS signatures.
// In this variant, public keys are in G2 (larger) and signatures are in G1 (smaller).
//
// Parameters:
//   - sid: Unique session identifier
//   - curveFamily: The pairing-friendly curve family to use
//   - shard: The party's secret shard
//   - quorum: The set of parties participating in signing
//   - rogueKeyAlg: The rogue key prevention algorithm (Basic, MessageAugmentation, or POP)
//   - tape: The transcript for domain separation
//
// Returns an error if any parameter is invalid or the quorum is not authorized.
func NewLongKeyCosigner[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	sid network.SID,
	curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S],
	shard *boldyreva02.Shard[P2, FE2, P1, FE1, E, S],
	quorum network.Quorum,
	rogueKeyAlg bls.RogueKeyPreventionAlgorithm,
	tape ts.Transcript,
) (*Cosigner[P2, FE2, P1, FE1, E, S], error) {
	if curveFamily == nil {
		return nil, ErrInvalidArgument.WithMessage("curveFamily is nil")
	}
	if tape == nil {
		return nil, ErrInvalidArgument.WithMessage("transcript is nil")
	}
	if !shard.AccessStructure().IsAuthorized(quorum.List()...) {
		return nil, ErrInvalidArgument.WithMessage("quorum is not authorized in the access structure")
	}
	if !bls.RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, ErrInvalidArgument.WithMessage("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	dst := fmt.Sprintf("%s-%d-%s-%d-%d", transcriptLabel, sid, curveFamily.Name(), bls.LongKey, rogueKeyAlg)
	tape.AppendDomainSeparator(dst)
	scheme, err := bls.NewLongKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create BLS long key scheme")
	}
	shareAsPrivateKey, err := shard.AsBLSPrivateKey()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to convert shard to BLS private key")
	}
	blsDst, err := scheme.CipherSuite().GetDst(rogueKeyAlg, bls.LongKey)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to get BLS destination for rogue key prevention algorithm")
	}
	return &Cosigner[P2, FE2, P1, FE1, E, S]{
		sid:               sid,
		shard:             shard,
		quorum:            quorum,
		tape:              tape,
		scheme:            scheme,
		shareAsPrivateKey: shareAsPrivateKey,
		targetRogueKeyAlg: rogueKeyAlg,
		targetDst:         blsDst,
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
	var sigmaPopI *bls.Signature[SG, SGFE, PK, PKFE, E, S]
	switch c.targetRogueKeyAlg {
	case bls.Basic:
	case bls.MessageAugmentation:
		message, err = bls.AugmentMessage(message, c.shard.PublicKey().Value())
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to augment message")
		}
	case bls.POP:
		popMsg := c.Shard().PublicKey().Bytes()
		popDst := c.scheme.CipherSuite().GetPopDst(c.Variant())
		popSigner, err := c.scheme.Signer(c.shareAsPrivateKey, bls.SignWithCustomDST[PK](popDst))
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to create signer for POP")
		}
		sigmaPopI, err = popSigner.Sign(popMsg)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to sign POP message")
		}
	default:
		return nil, ErrInvalidArgument.WithMessage("unsupported rogue key prevention algorithm: %d", c.targetRogueKeyAlg)
	}
	signer, err := c.scheme.Signer(c.shareAsPrivateKey, bls.SignWithCustomDST[PK](c.targetDst))
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create signer")
	}
	sigmaI, err := signer.Sign(message)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to sign message")
	}
	c.round++
	return &boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S]{
		SigmaI:    sigmaI,
		SigmaPopI: sigmaPopI,
	}, nil
}
