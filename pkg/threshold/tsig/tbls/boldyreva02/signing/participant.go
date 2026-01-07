package signing

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls/boldyreva02"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const transcriptLabel = "BRON_CRYPTO_TBLS_BOLDYREVA-"

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

func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) SharingID() sharing.ID {
	return c.shard.Share().ID()
}

func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) Quorum() network.Quorum {
	if c == nil {
		return nil
	}
	return c.quorum
}

func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) Shard() *boldyreva02.Shard[PK, PKFE, SG, SGFE, E, S] {
	if c == nil {
		return nil
	}
	return c.shard
}

func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) Variant() bls.Variant {
	return c.scheme.Variant()
}

func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) TargetRogueKeyPreventionAlgorithm() bls.RogueKeyPreventionAlgorithm {
	return c.targetRogueKeyAlg
}

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
		return nil, errs.NewIsNil("curveFamily")
	}
	if tape == nil {
		return nil, errs.NewIsNil("transcript")
	}
	if shard == nil {
		return nil, errs.NewIsNil("shard")
	}
	if quorum == nil {
		return nil, errs.NewIsNil("quorum")
	}
	if !bls.RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, errs.NewType("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	if !shard.AccessStructure().IsAuthorized(quorum.List()...) {
		return nil, errs.NewArgument("quorum is not authorized in the access structure")
	}
	dst := fmt.Sprintf("%s-%d-%s-%d-%d", transcriptLabel, sid, curveFamily.Name(), bls.ShortKey, rogueKeyAlg)
	tape.AppendDomainSeparator(dst)
	scheme, err := bls.NewShortKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create BLS short key scheme")
	}
	shareAsPrivateKey, err := shard.AsBLSPrivateKey()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to convert shard to BLS private key")
	}
	blsDst, err := scheme.CipherSuite().GetDst(rogueKeyAlg, bls.ShortKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get BLS destination for rogue key prevention algorithm")
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
		return nil, errs.NewIsNil("curveFamily")
	}
	if tape == nil {
		return nil, errs.NewIsNil("transcript")
	}
	if !shard.AccessStructure().IsAuthorized(quorum.List()...) {
		return nil, errs.NewArgument("quorum is not authorized in the access structure")
	}
	if !bls.RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, errs.NewType("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	dst := fmt.Sprintf("%s-%d-%s-%d-%d", transcriptLabel, sid, curveFamily.Name(), bls.LongKey, rogueKeyAlg)
	tape.AppendDomainSeparator(dst)
	scheme, err := bls.NewLongKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create BLS long key scheme")
	}
	shareAsPrivateKey, err := shard.AsBLSPrivateKey()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to convert shard to BLS private key")
	}
	blsDst, err := scheme.CipherSuite().GetDst(rogueKeyAlg, bls.LongKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get BLS destination for rogue key prevention algorithm")
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

func (c *Cosigner[PK, PKFE, SG, SGFE, E, S]) ProducePartialSignature(message []byte) (*boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S], error) {
	if c.round != 1 {
		return nil, errs.NewRound("ProducePartialSignature can only be called in round 1, current round: %d", c.round)
	}
	if len(message) == 0 {
		return nil, errs.NewArgument("message cannot be empty")
	}
	var err error
	var sigmaPopI *bls.Signature[SG, SGFE, PK, PKFE, E, S]
	switch c.targetRogueKeyAlg {
	case bls.Basic:
	case bls.MessageAugmentation:
		message, err = bls.AugmentMessage(message, c.shard.PublicKey().Value())
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to augment message")
		}
	case bls.POP:
		popMsg := c.Shard().PublicKey().Bytes()
		popDst := c.scheme.CipherSuite().GetPopDst(c.Variant())
		popSigner, err := c.scheme.Signer(c.shareAsPrivateKey, bls.SignWithCustomDST[PK](popDst))
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create signer for POP")
		}
		sigmaPopI, err = popSigner.Sign(popMsg)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to sign POP message")
		}
	default:
		return nil, errs.NewType("unsupported rogue key prevention algorithm: %d", c.targetRogueKeyAlg)
	}
	signer, err := c.scheme.Signer(c.shareAsPrivateKey, bls.SignWithCustomDST[PK](c.targetDst))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create signer")
	}
	sigmaI, err := signer.Sign(message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to sign message")
	}
	c.round++
	return &boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S]{
		SigmaI:    sigmaI,
		SigmaPopI: sigmaPopI,
	}, nil
}
