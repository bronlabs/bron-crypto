package bls

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

func NewShortKeyScheme[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FiniteFieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FiniteFieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S], rogueKeyAlg RogueKeyPreventionAlgorithm) (*Scheme[P1, FE1, P2, FE2, E, S], error) {
	cipherSuite, err := newScheme(curveFamily, rogueKeyAlg)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create cipher suite")
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

func NewLongKeyScheme[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FiniteFieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FiniteFieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S], rogueKeyAlg RogueKeyPreventionAlgorithm) (*Scheme[P2, FE2, P1, FE1, E, S], error) {
	cipherSuite, err := newScheme(curveFamily, rogueKeyAlg)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create cipher suite")
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
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FiniteFieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FiniteFieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S], rogueKeyAlg RogueKeyPreventionAlgorithm) (*CipherSuite, error) {
	if curveFamily == nil {
		return nil, errs.NewIsNil("curveFamily")
	}
	var cipherSuite *CipherSuite
	switch curveFamily.Name() {
	case bls12381.FamilyName:
		cipherSuite = BLS12381CipherSuite()
	default:
		return nil, errs.NewType("no ciphersuite for curve family %s", curveFamily.Name())
	}
	if !RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, errs.NewType("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	return cipherSuite, nil
}

type Scheme[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FiniteFieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FiniteFieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],

] struct {
	variant           Variant
	rogueKeyAlg       RogueKeyPreventionAlgorithm
	cipherSuite       *CipherSuite
	keySubGroup       curves.PairingFriendlyCurve[PK, PKFE, SG, SGFE, E, S]
	signatureSubGroup curves.PairingFriendlyCurve[SG, SGFE, PK, PKFE, E, S]
}

func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) Name() signatures.Name {
	return Name
}

func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) Variant() Variant {
	return s.variant
}

func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) RogueKeyPreventionAlgorithm() RogueKeyPreventionAlgorithm {
	return s.rogueKeyAlg
}

func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) CipherSuite() *CipherSuite {
	if s == nil {
		return nil
	}
	return s.cipherSuite
}

func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) KeySubGroup() curves.PairingFriendlyCurve[PK, PKFE, SG, SGFE, E, S] {
	if s == nil {
		return nil
	}
	return s.keySubGroup
}

func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) SignatureSubGroup() curves.PairingFriendlyCurve[SG, SGFE, PK, PKFE, E, S] {
	if s == nil {
		return nil
	}
	return s.signatureSubGroup
}

func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) Keygen(opts ...KeyGeneratorOption[PK, PKFE, SG, SGFE, E, S]) (*KeyGenerator[PK, PKFE, SG, SGFE, E, S], error) {
	kg := &KeyGenerator[PK, PKFE, SG, SGFE, E, S]{
		group: s.keySubGroup,
	}
	for _, opt := range opts {
		if err := opt(kg); err != nil {
			return nil, errs.WrapFailed(err, "key generator option failed")
		}
	}
	return kg, nil
}

func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) Signer(privateKey *PrivateKey[PK, PKFE, SG, SGFE, E, S], opts ...SignerOption[PK, PKFE, SG, SGFE, E, S]) (*Signer[PK, PKFE, SG, SGFE, E, S], error) {
	if privateKey == nil {
		return nil, errs.NewIsNil("privateKey")
	}
	out := &Signer[PK, PKFE, SG, SGFE, E, S]{
		privateKey:        privateKey,
		rogueKeyAlg:       s.rogueKeyAlg,
		cipherSuite:       s.cipherSuite,
		signatureSubGroup: s.signatureSubGroup,
		variant:           s.variant,
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "verifier option failed")
		}
	}
	return out, nil
}

func (s *Scheme[PK, PKFE, SG, SGFE, E, S]) Verifier(opts ...VerifierOption[PK, PKFE, SG, SGFE, E, S]) (*Verifier[PK, PKFE, SG, SGFE, E, S], error) {
	out := &Verifier[PK, PKFE, SG, SGFE, E, S]{
		cipherSuite:       s.cipherSuite,
		signatureSubGroup: s.signatureSubGroup,
		rogueKeyAlg:       s.rogueKeyAlg,
		variant:           s.variant,
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "verifier option failed")
		}
	}
	return out, nil
}

func (*Scheme[PK, PKFE, SG, SGFE, E, S]) AggregateSignatures(sigs ...*Signature[SG, SGFE, PK, PKFE, E, S]) (*Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if sigs == nil {
		return nil, errs.NewIsNil("signature")
	}
	return AggregateAll[PK](sigs)
}

func _[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FiniteFieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FiniteFieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
]() {
	var (
		_ signatures.Scheme[
			*PrivateKey[P1, FE1, P2, FE2, E, S], *PublicKey[P1, FE1, P2, FE2, E, S],
			[]byte, *Signature[P2, FE2, P1, FE1, E, S],
			*KeyGenerator[P1, FE1, P2, FE2, E, S], *Signer[P1, FE1, P2, FE2, E, S], *Verifier[P1, FE1, P2, FE2, E, S],
		] = (*Scheme[P1, FE1, P2, FE2, E, S])(nil)

		_ signatures.Scheme[
			*PrivateKey[P2, FE2, P1, FE1, E, S], *PublicKey[P2, FE2, P1, FE1, E, S],
			[]byte, *Signature[P1, FE1, P2, FE2, E, S],
			*KeyGenerator[P2, FE2, P1, FE1, E, S], *Signer[P2, FE2, P1, FE1, E, S], *Verifier[P2, FE2, P1, FE1, E, S],
		] = (*Scheme[P2, FE2, P1, FE1, E, S])(nil)

		_ signatures.AggregatableScheme[
			*PrivateKey[P1, FE1, P2, FE2, E, S], *PublicKey[P1, FE1, P2, FE2, E, S],
			[]byte, *Signature[P2, FE2, P1, FE1, E, S],
			*KeyGenerator[P1, FE1, P2, FE2, E, S], *Signer[P1, FE1, P2, FE2, E, S], *Verifier[P1, FE1, P2, FE2, E, S],
			*Signature[P2, FE2, P1, FE1, E, S],
		] = (*Scheme[P1, FE1, P2, FE2, E, S])(nil)

		_ signatures.AggregatableScheme[
			*PrivateKey[P2, FE2, P1, FE1, E, S], *PublicKey[P2, FE2, P1, FE1, E, S],
			[]byte, *Signature[P1, FE1, P2, FE2, E, S],
			*KeyGenerator[P2, FE2, P1, FE1, E, S], *Signer[P2, FE2, P1, FE1, E, S], *Verifier[P2, FE2, P1, FE1, E, S],
			*Signature[P1, FE1, P2, FE2, E, S],
		] = (*Scheme[P2, FE2, P1, FE1, E, S])(nil)
	)
}
