package vanilla

import (
	"hash"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

type (
	PublicKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]]  = schnorrlike.PublicKey[GE, S]
	PrivateKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = schnorrlike.PrivateKey[GE, S]
	Signature[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]]  = schnorrlike.Signature[GE, S]
	Message                                                                         = []byte
)

const VariantType schnorrlike.VariantType = "Schnorr"

func NewPublicKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](point GE) (*PublicKey[GE, S], error) {
	return schnorrlike.NewPublicKey(point)
}

func NewPrivateKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](scalar S, pk *PublicKey[GE, S]) (*PrivateKey[GE, S], error) {
	return schnorrlike.NewPrivateKey(scalar, pk)
}

func NewScheme[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](
	group algebra.PrimeGroup[GE, S],
	f func() hash.Hash,
	responseOperatorIsNegative bool,
	challengeElementsAreLittleEndian bool,
	prng io.Reader,
) (*Scheme[GE, S], error) {
	if group == nil {
		return nil, errs.NewIsNil("group")
	}
	if f == nil {
		return nil, errs.NewIsNil("hash function")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	sf, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewType("group")
	}
	return &Scheme[GE, S]{
		group:                            group,
		sf:                               sf,
		h:                                f,
		prng:                             prng,
		responseOperatorIsNegative:       responseOperatorIsNegative,
		challengeElementsAreLittleEndian: challengeElementsAreLittleEndian,
	}, nil
}

func VariantWithHashFunc[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](
	f func() hash.Hash,
) VariantOption[GE, S] {
	return func(v *Variant[GE, S]) error {
		if v == nil {
			return errs.NewIsNil("variant")
		}
		if f == nil {
			return errs.NewIsNil("hash function")
		}
		v.h = f
		return nil
	}
}

type Scheme[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	group                            algebra.PrimeGroup[GE, S]
	sf                               algebra.PrimeField[S]
	h                                func() hash.Hash
	prng                             io.Reader // PRNG used to generate nonces
	responseOperatorIsNegative       bool
	challengeElementsAreLittleEndian bool
}

func (*Scheme[GE, S]) Name() signatures.Name {
	return schnorrlike.Name
}

func (s *Scheme[GE, S]) Variant(opts ...VariantOption[GE, S]) (*Variant[GE, S], error) {
	if s.group == nil {
		return nil, errs.NewIsNil("group")
	}
	if s.sf == nil {
		return nil, errs.NewIsNil("scalar field")
	}
	variant := &Variant[GE, S]{
		g:                                s.group,
		sf:                               s.sf,
		h:                                s.h,
		prng:                             s.prng,
		responseOperatorIsNegative:       s.responseOperatorIsNegative,
		challengeElementsAreLittleEndian: s.challengeElementsAreLittleEndian,
	}
	for _, opt := range opts {
		if err := opt(variant); err != nil {
			return nil, errs.WrapFailed(err, "variant option failed")
		}
	}
	return variant, nil
}

func (s *Scheme[GE, S]) Keygen(opts ...KeyGeneratorOption[GE, S]) (*KeyGenerator[GE, S], error) {
	out := &KeyGenerator[GE, S]{
		KeyGeneratorTrait: schnorrlike.KeyGeneratorTrait[GE, S]{
			Grp: s.group,
			SF:  s.sf,
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "key generator option failed")
		}
	}
	return out, nil
}

func (s *Scheme[GE, S]) Signer(privateKey *PrivateKey[GE, S], opts ...SignerOption[GE, S]) (*Signer[GE, S], error) {
	if privateKey == nil {
		return nil, errs.NewArgument("private key is nil")
	}
	verifier, err := s.Verifier()
	if err != nil {
		return nil, errs.WrapFailed(err, "verifier creation failed")
	}
	variant, err := s.Variant()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct variant")
	}
	out := &Signer[GE, S]{
		schnorrlike.RandomisedSignerTrait[*Variant[GE, S], GE, S, Message]{
			Sk:       privateKey,
			V:        variant,
			Verifier: verifier,
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "signer option failed")
		}
	}
	return out, nil
}

func (s *Scheme[GE, S]) Verifier(opts ...VerifierOption[GE, S]) (*Verifier[GE, S], error) {
	variant, err := s.Variant()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct variant")
	}
	out := &Verifier[GE, S]{
		VerifierTrait: schnorrlike.VerifierTrait[*Variant[GE, S], GE, S, Message]{
			V:                          variant,
			ResponseOperatorIsNegative: s.responseOperatorIsNegative,
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "verifier option failed")
		}
	}
	return out, nil
}

func (s *Scheme[GE, S]) PartialSignatureVerifier(
	publicKey *PublicKey[GE, S],
	opts ...signatures.VerifierOption[*Verifier[GE, S], *PublicKey[GE, S], Message, *Signature[GE, S]],
) (schnorrlike.Verifier[*Variant[GE, S], GE, S, Message], error) {
	if publicKey == nil {
		return nil, errs.NewArgument("public key is nil or invalid")
	}
	verifier, err := s.Verifier(opts...)
	if err != nil {
		return nil, errs.WrapFailed(err, "verifier creation failed")
	}
	verifier.VerifierTrait.ChallengePublicKey = publicKey
	return verifier, nil
}

type KeyGeneratorOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = signatures.KeyGeneratorOption[*KeyGenerator[GE, S], *PrivateKey[GE, S], *PublicKey[GE, S]]

type KeyGenerator[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	schnorrlike.KeyGeneratorTrait[GE, S]
}

type SignerOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = signatures.SignerOption[*Signer[GE, S], Message, *Signature[GE, S]]

type Signer[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	schnorrlike.RandomisedSignerTrait[*Variant[GE, S], GE, S, Message]
}

func (sg *Signer[GE, S]) Variant() *Variant[GE, S] {
	if sg == nil {
		panic(errs.NewIsNil("signer"))
	}
	return sg.V
}

type VerifierOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = signatures.VerifierOption[*Verifier[GE, S], *PublicKey[GE, S], Message, *Signature[GE, S]]

type Verifier[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	schnorrlike.VerifierTrait[*Variant[GE, S], GE, S, Message]
}

func (v *Verifier[GE, S]) Variant() *Variant[GE, S] {
	if v == nil {
		panic(errs.NewIsNil("verifier"))
	}
	return v.V
}

type VariantOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = schnorrlike.VariantOption[*Variant[GE, S], GE, S, Message]
type Variant[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	g                                algebra.PrimeGroup[GE, S]
	sf                               algebra.PrimeField[S]
	h                                func() hash.Hash
	prng                             io.Reader
	responseOperatorIsNegative       bool
	challengeElementsAreLittleEndian bool
}

func (v *Variant[GE, S]) Type() schnorrlike.VariantType {
	return VariantType
}

func (v *Variant[GE, S]) HashFunc() func() hash.Hash {
	if v.h == nil {
		return nil
	}
	return v.h
}

func (v *Variant[GE, S]) ComputeNonceCommitment() (GE, S, error) {
	if v == nil {
		return *new(GE), *new(S), errs.NewIsNil("variant")
	}
	return schnorrlike.ComputeGenericNonceCommitment(v.g, v.prng)
}

func (v *Variant[GE, S]) ComputeChallenge(nonceCommitment GE, publicKeyValue GE, message Message) (S, error) {
	if v == nil {
		return *new(S), errs.NewIsNil("variant")
	}
	if utils.IsNil(nonceCommitment) {
		return *new(S), errs.NewIsNil("nonce commitment")
	}
	if utils.IsNil(publicKeyValue) {
		return *new(S), errs.NewIsNil("public key value")
	}
	if utils.IsNil(message) {
		return *new(S), errs.NewIsNil("message")
	}
	return schnorrlike.MakeGenericChallenge(v.sf, v.h, v.challengeElementsAreLittleEndian, nonceCommitment.Bytes(), publicKeyValue.Bytes(), message)
}

func (v *Variant[GE, S]) ComputeResponse(privateKeyValue, nonce, challenge S) (S, error) {
	if v == nil {
		return *new(S), errs.NewIsNil("variant")
	}
	if utils.IsNil(privateKeyValue) {
		return *new(S), errs.NewIsNil("private key value")
	}
	if utils.IsNil(nonce) {
		return *new(S), errs.NewIsNil("nonce")
	}
	if utils.IsNil(challenge) {
		return *new(S), errs.NewIsNil("challenge")
	}
	return schnorrlike.ComputeGenericResponse(privateKeyValue, nonce, challenge, v.responseOperatorIsNegative)
}

func (v *Variant[GE, S]) SerializeSignature(signature *Signature[GE, S]) ([]byte, error) {
	if v == nil {
		return nil, errs.NewIsNil("variant")
	}
	if signature == nil {
		return nil, errs.NewIsNil("signature")
	}
	if utils.IsNil(signature.R) {
		return nil, errs.NewIsNil("signature.R")
	}
	if utils.IsNil(signature.S) {
		return nil, errs.NewIsNil("signature.S")
	}
	// Vanilla Schnorr signature format: (R, s)
	// Note: E (challenge) can be recomputed during verification
	out := append(signature.R.Bytes(), signature.S.Bytes()...)
	return out, nil
}

func (*Variant[GE, S]) NonceIsFunctionOfMessage() bool {
	return false
}

func (*Variant[GE, S]) CorrectPartialNonceParity(aggregatedNonceCommitment GE, nonce S) (GE, S, error) {
	if utils.IsNil(aggregatedNonceCommitment) {
		return *new(GE), *new(S), errs.NewIsNil("aggregated nonce commitment")
	}
	if utils.IsNil(nonce) {
		return *new(GE), *new(S), errs.NewIsNil("nonce")
	}
	// No change in MPC context
	group, ok := aggregatedNonceCommitment.Structure().(algebra.PrimeGroup[GE, S])
	if !ok {
		return *new(GE), *new(S), errs.NewType("aggregated nonce commitment")
	}
	R := group.ScalarBaseOp(nonce)
	return R, nonce, nil
}

func (*Variant[GE, S]) CorrectAdditiveSecretShareParity(publicKey *schnorrlike.PublicKey[GE, S], share *additive.Share[S]) (*additive.Share[S], error) {
	if publicKey == nil || share == nil {
		return nil, errs.NewIsNil("public key or secret share is nil")
	}
	// No change in MPC context
	return share.Clone(), nil
}

func _[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]]() {
	var (
		_ schnorrlike.Variant[GE, S, Message]         = (*Variant[GE, S])(nil)
		_ tschnorr.MPCFriendlyVariant[GE, S, Message] = (*Variant[GE, S])(nil)
	)
}
