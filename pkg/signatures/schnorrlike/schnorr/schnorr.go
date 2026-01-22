// Package vanilla provides a configurable generic Schnorr signature implementation.
//
// Unlike BIP-340 or Mina which have fixed parameter choices, this package allows
// customization of all aspects of the Schnorr signature scheme:
//   - Elliptic curve group (any prime-order group)
//   - Hash function (SHA-256, SHA-3, BLAKE2, etc.)
//   - Response equation sign (s = k + ex or s = k - ex)
//   - Byte ordering (big-endian or little-endian)
//   - Nonce parity constraints (optional even-y requirement)
//
// This flexibility makes it suitable for implementing custom Schnorr variants
// or for use with non-standard curves.
//
// # Example Usage
//
//	scheme, _ := vanilla.NewScheme(
//	    secp256k1.NewCurve(),           // Curve
//	    sha256.New,                      // Hash function
//	    false,                           // Response operator not negative
//	    false,                           // Big-endian challenge elements
//	    nil,                             // No nonce parity constraint
//	    rand.Reader,                     // Random nonce generation
//	)
//	signer, _ := scheme.Signer(privateKey)
//	signature, _ := signer.Sign(message)
package vanilla

import (
	"hash"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
	"github.com/bronlabs/errs-go/errs"
)

type (
	// PublicKey is a generic Schnorr public key parameterized by curve and scalar types.
	PublicKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = schnorrlike.PublicKey[GE, S]
	// PrivateKey is a generic Schnorr private key parameterized by curve and scalar types.
	PrivateKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = schnorrlike.PrivateKey[GE, S]
	// Signature is a generic Schnorr signature parameterized by curve and scalar types.
	Signature[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = schnorrlike.Signature[GE, S]
	// Message is a byte slice to be signed.
	Message = []byte
)

// VariantType identifies this as the vanilla Schnorr variant.
const VariantType schnorrlike.VariantType = "Schnorr"

// NewPublicKey creates a Schnorr public key from a curve point.
func NewPublicKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](point GE) (*PublicKey[GE, S], error) {
	pk, err := schnorrlike.NewPublicKey(point)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Schnorr public key")
	}
	return pk, nil
}

// NewPrivateKey creates a Schnorr private key from a scalar and its public key.
func NewPrivateKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](scalar S, pk *PublicKey[GE, S]) (*PrivateKey[GE, S], error) {
	sk, err := schnorrlike.NewPrivateKey(scalar, pk)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Schnorr private key")
	}
	return sk, nil
}

// NewScheme creates a configurable Schnorr signature scheme.
//
// Parameters:
//   - group: The elliptic curve group (must be prime-order)
//   - f: Hash function constructor for challenge computation
//   - responseOperatorIsNegative: If true, uses s = k - ex instead of s = k + ex
//   - challengeElementsAreLittleEndian: If true, reverses bytes before hashing
//   - shouldNegateNonce: Optional callback to enforce nonce parity (e.g., even y)
//   - prng: Random source for nonce generation
func NewScheme[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](
	group algebra.PrimeGroup[GE, S],
	f func() hash.Hash,
	responseOperatorIsNegative bool,
	challengeElementsAreLittleEndian bool,
	shouldNegateNonce func(nonceCommitment GE) bool,
	prng io.Reader,
) (*Scheme[GE, S], error) {
	if group == nil {
		return nil, ErrInvalidArgument.WithMessage("group is nil")
	}
	if f == nil {
		return nil, ErrInvalidArgument.WithMessage("hash function is nil")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng is nil")
	}
	sf, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, ErrInvalidArgument.WithMessage("group type assertion failed")
	}
	return &Scheme[GE, S]{
		vr: &Variant[GE, S]{
			g:                                group,
			sf:                               sf,
			h:                                f,
			prng:                             prng,
			shouldNegateNonce:                shouldNegateNonce,
			responseOperatorIsNegative:       responseOperatorIsNegative,
			challengeElementsAreLittleEndian: challengeElementsAreLittleEndian,
		},
	}, nil
}

// Scheme is a configurable generic Schnorr signature scheme.
// It can be parameterized with any prime-order elliptic curve group.
type Scheme[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	vr *Variant[GE, S]
}

// Name returns the signature scheme identifier ("SchnorrLike").
func (*Scheme[GE, S]) Name() signatures.Name {
	return schnorrlike.Name
}

// Variant returns the Schnorr variant configuration for this scheme.
func (s *Scheme[GE, S]) Variant() *Variant[GE, S] {
	return s.vr
}

// Keygen creates a key generator for this Schnorr scheme.
func (s *Scheme[GE, S]) Keygen(opts ...KeyGeneratorOption[GE, S]) (*KeyGenerator[GE, S], error) {
	out := &KeyGenerator[GE, S]{
		KeyGeneratorTrait: schnorrlike.KeyGeneratorTrait[GE, S]{
			Grp: s.vr.g,
			SF:  s.vr.sf,
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.Wrap(err).WithMessage("key generator option failed")
		}
	}
	return out, nil
}

// Signer creates a signer for producing Schnorr signatures.
func (s *Scheme[GE, S]) Signer(privateKey *PrivateKey[GE, S], opts ...SignerOption[GE, S]) (*Signer[GE, S], error) {
	if privateKey == nil {
		return nil, ErrInvalidArgument.WithMessage("private key is nil")
	}
	verifier, err := s.Verifier()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("verifier creation failed")
	}
	out := &Signer[GE, S]{
		schnorrlike.SignerTrait[*Variant[GE, S], GE, S, Message]{
			Sk:       privateKey,
			V:        s.vr,
			Verifier: verifier,
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.Wrap(err).WithMessage("signer option failed")
		}
	}
	return out, nil
}

// Verifier creates a verifier for validating Schnorr signatures.
func (s *Scheme[GE, S]) Verifier(opts ...VerifierOption[GE, S]) (*Verifier[GE, S], error) {
	out := &Verifier[GE, S]{
		VerifierTrait: schnorrlike.VerifierTrait[*Variant[GE, S], GE, S, Message]{
			V:                          s.vr,
			ResponseOperatorIsNegative: s.vr.responseOperatorIsNegative,
			ChallengePublicKey:         nil,
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.Wrap(err).WithMessage("verifier option failed")
		}
	}
	return out, nil
}

// PartialSignatureVerifier creates a verifier for threshold/partial signatures.
func (s *Scheme[GE, S]) PartialSignatureVerifier(
	publicKey *PublicKey[GE, S],
	opts ...signatures.VerifierOption[*Verifier[GE, S], *PublicKey[GE, S], Message, *Signature[GE, S]],
) (schnorrlike.Verifier[*Variant[GE, S], GE, S, Message], error) {
	if publicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("public key is nil or invalid")
	}
	verifier, err := s.Verifier(opts...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("verifier creation failed")
	}
	verifier.ChallengePublicKey = publicKey
	return verifier, nil
}

// KeyGeneratorOption configures key generation behaviour.
type KeyGeneratorOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = signatures.KeyGeneratorOption[*KeyGenerator[GE, S], *PrivateKey[GE, S], *PublicKey[GE, S]]

// KeyGenerator creates Schnorr key pairs for the configured curve.
type KeyGenerator[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	schnorrlike.KeyGeneratorTrait[GE, S]
}

// SignerOption configures signing behaviour.
type SignerOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = signatures.SignerOption[*Signer[GE, S], Message, *Signature[GE, S]]

// Signer produces Schnorr signatures using random nonce generation.
type Signer[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	schnorrlike.SignerTrait[*Variant[GE, S], GE, S, Message]
}

// Variant returns the Schnorr variant used by this signer.
func (sg *Signer[GE, S]) Variant() *Variant[GE, S] {
	if sg == nil {
		panic(ErrInvalidArgument.WithMessage("signer is nil"))
	}
	return sg.V
}

// VerifierOption configures verification behaviour.
type VerifierOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = signatures.VerifierOption[*Verifier[GE, S], *PublicKey[GE, S], Message, *Signature[GE, S]]

// Verifier validates Schnorr signatures.
type Verifier[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	schnorrlike.VerifierTrait[*Variant[GE, S], GE, S, Message]
}

// Variant returns the Schnorr variant used by this verifier.
func (v *Verifier[GE, S]) Variant() *Variant[GE, S] {
	if v == nil {
		panic(ErrInvalidArgument.WithMessage("verifier is nil"))
	}
	return v.V
}

// Variant implements variant-specific behaviour for vanilla Schnorr.
// It stores all configurable parameters for the signature scheme.
type Variant[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	g                                algebra.PrimeGroup[GE, S]     // underlying group
	sf                               algebra.PrimeField[S]         // Scalar field of the underlying group
	h                                func() hash.Hash              // Hash function for challenges
	prng                             io.Reader                     // Random source for nonces
	responseOperatorIsNegative       bool                          // Use s = k - ex instead of s = k + ex
	challengeElementsAreLittleEndian bool                          // Reverse byte order before hashing
	shouldNegateNonce                func(nonceCommitment GE) bool // Optional parity constraint callback
}

// Type returns the variant identifier "Schnorr".
func (*Variant[GE, S]) Type() schnorrlike.VariantType {
	return VariantType
}

// HashFunc returns the configured hash function constructor.
func (v *Variant[GE, S]) HashFunc() func() hash.Hash {
	if v.h == nil {
		return nil
	}
	return v.h
}

// ComputeNonceCommitment generates a random nonce k and commitment R = k·G.
// If shouldNegateNonce was configured, applies parity correction to k.
func (v *Variant[GE, S]) ComputeNonceCommitment() (R GE, k S, err error) {
	if v == nil {
		return *new(GE), *new(S), ErrInvalidArgument.WithMessage("variant is nil")
	}
	ge, s, err := schnorrlike.ComputeGenericNonceCommitment(v.g, v.prng, v.shouldNegateNonce)
	if err != nil {
		return *new(GE), *new(S), errs.Wrap(err).WithMessage("failed to compute nonce commitment")
	}
	return ge, s, nil
}

// ComputeChallenge computes the Fiat-Shamir challenge: e = H(R || P || m) mod n.
// Uses the configured hash function and byte ordering.
func (v *Variant[GE, S]) ComputeChallenge(nonceCommitment, publicKeyValue GE, message Message) (S, error) {
	if v == nil {
		return *new(S), ErrInvalidArgument.WithMessage("variant is nil")
	}
	if utils.IsNil(nonceCommitment) {
		return *new(S), ErrInvalidArgument.WithMessage("nonce commitment is nil")
	}
	if utils.IsNil(publicKeyValue) {
		return *new(S), ErrInvalidArgument.WithMessage("public key value is nil")
	}
	if utils.IsNil(message) {
		return *new(S), ErrInvalidArgument.WithMessage("message is nil")
	}
	challenge, err := schnorrlike.MakeGenericChallenge(v.sf, v.h, v.challengeElementsAreLittleEndian, nonceCommitment.Bytes(), publicKeyValue.Bytes(), message)
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("failed to compute Schnorr challenge")
	}
	return challenge, nil
}

// ComputeResponse computes the signature response: s = k ± e·x mod n.
// The sign depends on the responseOperatorIsNegative configuration.
func (v *Variant[GE, S]) ComputeResponse(privateKeyValue, nonce, challenge S) (S, error) {
	if v == nil {
		return *new(S), ErrInvalidArgument.WithMessage("variant is nil")
	}
	if utils.IsNil(privateKeyValue) {
		return *new(S), ErrInvalidArgument.WithMessage("private key value is nil")
	}
	if utils.IsNil(nonce) {
		return *new(S), ErrInvalidArgument.WithMessage("nonce is nil")
	}
	if utils.IsNil(challenge) {
		return *new(S), ErrInvalidArgument.WithMessage("challenge is nil")
	}
	response, err := schnorrlike.ComputeGenericResponse(privateKeyValue, nonce, challenge, v.responseOperatorIsNegative)
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("failed to compute Schnorr response")
	}
	return response, nil
}

// SerializeSignature encodes the signature as (R || s) in native byte format.
func (v *Variant[GE, S]) SerializeSignature(signature *Signature[GE, S]) ([]byte, error) {
	if v == nil {
		return nil, ErrInvalidArgument.WithMessage("variant is nil")
	}
	if signature == nil {
		return nil, ErrInvalidArgument.WithMessage("signature is nil")
	}
	if utils.IsNil(signature.R) {
		return nil, ErrInvalidArgument.WithMessage("signature.R is nil")
	}
	if utils.IsNil(signature.S) {
		return nil, ErrInvalidArgument.WithMessage("signature.S is nil")
	}
	// Vanilla Schnorr signature format: (R, s)
	// Note: E (challenge) can be recomputed during verification
	out := append(signature.R.Bytes(), signature.S.Bytes()...)
	return out, nil
}

// NonceIsFunctionOfMessage returns false since vanilla Schnorr uses random nonces.
func (*Variant[GE, S]) NonceIsFunctionOfMessage() bool {
	return false
}

// CorrectPartialNonceParity is a no-op for vanilla Schnorr (no parity constraints).
// Returns the nonce and its commitment unchanged.
func (*Variant[GE, S]) CorrectPartialNonceParity(aggregatedNonceCommitment GE, nonce S) (R GE, correctedNonce S, err error) {
	if utils.IsNil(aggregatedNonceCommitment) {
		return *new(GE), *new(S), ErrInvalidArgument.WithMessage("aggregated nonce commitment is nil")
	}
	if utils.IsNil(nonce) {
		return *new(GE), *new(S), ErrInvalidArgument.WithMessage("nonce is nil")
	}
	// No change in MPC context
	group, ok := aggregatedNonceCommitment.Structure().(algebra.PrimeGroup[GE, S])
	if !ok {
		return *new(GE), *new(S), ErrInvalidArgument.WithMessage("aggregated nonce commitment type assertion failed")
	}
	R = group.ScalarBaseOp(nonce)
	return R, nonce, nil
}

// CorrectAdditiveSecretShareParity is a no-op for vanilla Schnorr (no parity constraints).
// Returns a clone of the share unchanged.
func (*Variant[GE, S]) CorrectAdditiveSecretShareParity(publicKey *schnorrlike.PublicKey[GE, S], share *additive.Share[S]) (*additive.Share[S], error) {
	if publicKey == nil || share == nil {
		return nil, ErrInvalidArgument.WithMessage("public key or secret share is nil")
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
