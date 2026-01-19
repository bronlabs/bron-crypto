package bls

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

// NewShortKeyScheme creates a BLS signature scheme with minimal public key size.
// Public keys reside in G1 (48 bytes compressed) and signatures in G2 (96 bytes compressed).
//
// This variant is preferred when public keys are transmitted or stored more frequently than
// signatures, as the smaller key size reduces bandwidth and storage costs.
//
// The rogueKeyAlg parameter specifies the rogue key attack prevention mechanism:
//   - Basic: requires distinct messages in aggregate signatures
//   - MessageAugmentation: prepends public key to messages before signing
//   - POP: requires proof of possession for each public key
func NewShortKeyScheme[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S], rogueKeyAlg RogueKeyPreventionAlgorithm) (*Scheme[P1, FE1, P2, FE2, E, S], error) {
	cipherSuite, err := newScheme(curveFamily, rogueKeyAlg)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create cipher suite")
	}
	keySubGroup := curveFamily.SourceSubGroup()
	signatureSubGroup := curveFamily.TwistedSubGroup()
	return &Scheme[P1, FE1, P2, FE2, E, S]{
		variant:           ShortKey,
		rogueKeyAlg:       rogueKeyAlg,
		cipherSuite:       cipherSuite,
		keySubGroup:       keySubGroup,
		signatureSubGroup: signatureSubGroup,
	}, nil
}

// NewLongKeyScheme creates a BLS signature scheme with minimal signature size.
// Public keys reside in G2 (96 bytes compressed) and signatures in G1 (48 bytes compressed).
//
// This variant is preferred when signatures are transmitted or stored more frequently than
// public keys, as the smaller signature size reduces bandwidth and storage costs.
//
// The rogueKeyAlg parameter specifies the rogue key attack prevention mechanism:
//   - Basic: requires distinct messages in aggregate signatures
//   - MessageAugmentation: prepends public key to messages before signing
//   - POP: requires proof of possession for each public key
func NewLongKeyScheme[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S], rogueKeyAlg RogueKeyPreventionAlgorithm) (*Scheme[P2, FE2, P1, FE1, E, S], error) {
	cipherSuite, err := newScheme(curveFamily, rogueKeyAlg)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create cipher suite")
	}
	keySubGroup := curveFamily.TwistedSubGroup()
	signatureSubGroup := curveFamily.SourceSubGroup()
	return &Scheme[P2, FE2, P1, FE1, E, S]{
		variant:           LongKey,
		rogueKeyAlg:       rogueKeyAlg,
		cipherSuite:       cipherSuite,
		keySubGroup:       keySubGroup,
		signatureSubGroup: signatureSubGroup,
	}, nil
}

func newScheme[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S], rogueKeyAlg RogueKeyPreventionAlgorithm) (*CipherSuite, error) {
	if curveFamily == nil {
		return nil, ErrInvalidArgument.WithMessage("curveFamily is nil")
	}
	var cipherSuite *CipherSuite
	switch curveFamily.Name() {
	case bls12381.FamilyName:
		cipherSuite = BLS12381CipherSuite()
	default:
		return nil, ErrNotSupported.WithMessage("no ciphersuite for curve family %s", curveFamily.Name())
	}
	if !RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, ErrNotSupported.WithMessage("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	return cipherSuite, nil
}

// Scheme represents a configured BLS signature scheme instance with a specific curve family,
// key/signature variant, and rogue key prevention algorithm.
//
// The Scheme provides factory methods for creating key generators, signers, and verifiers,
// as well as signature aggregation functionality.
type Scheme[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],

] struct {
	variant           Variant
	rogueKeyAlg       RogueKeyPreventionAlgorithm
	cipherSuite       *CipherSuite
	keySubGroup       curves.PairingFriendlyCurve[PK, PKFE, SG, SGFE, E, S]
	signatureSubGroup curves.PairingFriendlyCurve[SG, SGFE, PK, PKFE, E, S]
}

// Name returns the signature scheme identifier ("BLS").
func (*Scheme[PK, PKFE, SG, SGFE, E, S]) Name() signatures.Name {
	return Name
}

// Variant returns whether this scheme uses minimal public key size (ShortKey)
// or minimal signature size (LongKey).
func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) Variant() Variant {
	return s.variant
}

// RogueKeyPreventionAlgorithm returns the rogue key attack prevention mechanism
// configured for this scheme (Basic, MessageAugmentation, or POP).
func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) RogueKeyPreventionAlgorithm() RogueKeyPreventionAlgorithm {
	return s.rogueKeyAlg
}

// CipherSuite returns the cryptographic parameters including domain separation tags
// for hash-to-curve operations.
func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) CipherSuite() *CipherSuite {
	if s == nil {
		return nil
	}
	return s.cipherSuite
}

// KeySubGroup returns the elliptic curve subgroup used for public keys.
// For ShortKey: G1. For LongKey: G2.
func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) KeySubGroup() curves.PairingFriendlyCurve[PK, PKFE, SG, SGFE, E, S] {
	if s == nil {
		return nil
	}
	return s.keySubGroup
}

// SignatureSubGroup returns the elliptic curve subgroup used for signatures.
// For ShortKey: G2. For LongKey: G1.
func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) SignatureSubGroup() curves.PairingFriendlyCurve[SG, SGFE, PK, PKFE, E, S] {
	if s == nil {
		return nil
	}
	return s.signatureSubGroup
}

// Keygen creates a key generator for producing BLS key pairs.
// Options can be used to provide deterministic seed material.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.3
func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) Keygen(opts ...KeyGeneratorOption[PK, PKFE, SG, SGFE, E, S]) (*KeyGenerator[PK, PKFE, SG, SGFE, E, S], error) {
	kg := &KeyGenerator[PK, PKFE, SG, SGFE, E, S]{
		group: s.keySubGroup,
		seed:  nil,
	}
	for _, opt := range opts {
		if err := opt(kg); err != nil {
			return nil, errs2.Wrap(err).WithMessage("key generator option failed")
		}
	}
	return kg, nil
}

// Signer creates a signer for producing BLS signatures with the given private key.
// Options can be used to customise the domain separation tag.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.6
func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) Signer(privateKey *PrivateKey[PK, PKFE, SG, SGFE, E, S], opts ...SignerOption[PK, PKFE, SG, SGFE, E, S]) (*Signer[PK, PKFE, SG, SGFE, E, S], error) {
	if privateKey == nil {
		return nil, ErrInvalidArgument.WithMessage("privateKey is nil")
	}
	out := &Signer[PK, PKFE, SG, SGFE, E, S]{
		privateKey:        privateKey,
		rogueKeyAlg:       s.rogueKeyAlg,
		cipherSuite:       s.cipherSuite,
		signatureSubGroup: s.signatureSubGroup,
		variant:           s.variant,
		dst:               "",
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs2.Wrap(err).WithMessage("signer option failed")
		}
	}
	return out, nil
}

// Verifier creates a verifier for validating BLS signatures.
// Options can be used to customise the domain separation tag or provide proofs of possession.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.7
func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) Verifier(opts ...VerifierOption[PK, PKFE, SG, SGFE, E, S]) (*Verifier[PK, PKFE, SG, SGFE, E, S], error) {
	out := &Verifier[PK, PKFE, SG, SGFE, E, S]{
		cipherSuite:       s.cipherSuite,
		signatureSubGroup: s.signatureSubGroup,
		rogueKeyAlg:       s.rogueKeyAlg,
		variant:           s.variant,
		pops:              nil,
		dst:               "",
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs2.Wrap(err).WithMessage("verifier option failed")
		}
	}
	return out, nil
}

// AggregateSignatures combines multiple BLS signatures into a single aggregate signature
// via elliptic curve point addition. The resulting signature can be verified against
// the corresponding aggregate public key or set of public keys.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.8
func (*Scheme[PK, PKFE, SG, SGFE, E, S]) AggregateSignatures(sigs ...*Signature[SG, SGFE, PK, PKFE, E, S]) (*Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if sigs == nil {
		return nil, ErrInvalidArgument.WithMessage("signature is nil")
	}
	return AggregateAll[PK](sigs)
}
