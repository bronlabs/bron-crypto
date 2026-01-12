// Package schnorrlike provides a generic framework for Schnorr-like signature schemes.
//
// Schnorr signatures are digital signatures based on the discrete logarithm problem,
// originally proposed by Claus-Peter Schnorr in 1989. They convert an interactive
// identification protocol into a non-interactive signature scheme using the
// Fiat-Shamir heuristic.
//
// # Protocol Overview
//
// A Schnorr signature on message m with private key x and public key P = x·G consists of:
//  1. Generate random nonce k and compute commitment R = k·G
//  2. Compute challenge e = H(R || P || m)
//  3. Compute response s = k + e·x (or s = k - e·x depending on variant)
//
// The signature is (R, s) or (e, s) depending on the variant.
//
// Verification checks: s·G = R + e·P (or s·G = R - e·P for negative response variants)
//
// # Variants
//
// This package supports multiple Schnorr variants through the Variant interface:
//   - BIP-340: Bitcoin's Schnorr with x-only public keys and tagged hashing
//   - Mina: Schnorr on Pallas curve with Poseidon hashing
//   - Vanilla: Configurable generic Schnorr implementation
//
// Each variant can customize nonce generation, challenge computation, and response
// calculation while sharing common verification logic.
//
// # Threshold Signatures
//
// The framework supports threshold/MPC-friendly signatures through additional
// interfaces that handle parity corrections required by variants like BIP-340.
//
// References:
//   - Schnorr, C.P. (1991). Efficient signature generation by smart cards.
//     Journal of Cryptology, 4(3), 161-174.
//   - Fiat, A., & Shamir, A. (1987). How to prove yourself: Practical solutions
//     to identification and signature problems.
package schnorrlike

import (
	"hash"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

// Name is the signature scheme identifier for Schnorr-like signatures.
const Name signatures.Name = "SchnorrLike"

type (
	// VariantType identifies a specific Schnorr variant (e.g., "bip340", "mina", "Schnorr").
	VariantType string

	// Group represents an elliptic curve group suitable for Schnorr signatures.
	// It must be a prime-order group where the discrete logarithm problem is hard.
	Group[GE GroupElement[GE, S], S Scalar[S]] algebra.PrimeGroup[GE, S]

	// GroupElement represents a point on the elliptic curve.
	// Public keys and nonce commitments are group elements.
	GroupElement[GE algebra.PrimeGroupElement[GE, S], S Scalar[S]] algebra.PrimeGroupElement[GE, S]

	// ScalarField represents the field of scalars (integers modulo the group order).
	ScalarField[S Scalar[S]] algebra.PrimeField[S]

	// Scalar represents an element of the scalar field.
	// Private keys, nonces, challenges, and responses are scalars.
	Scalar[S algebra.PrimeFieldElement[S]] algebra.PrimeFieldElement[S]

	// KeyGenerator creates Schnorr key pairs.
	KeyGenerator[GE GroupElement[GE, S], S Scalar[S]] = signatures.KeyGenerator[*PrivateKey[GE, S], *PublicKey[GE, S]]

	// Signer creates Schnorr signatures using a private key.
	// It embeds the base Signer interface and provides access to the variant.
	Signer[VR Variant[GE, S, M], GE GroupElement[GE, S], S Scalar[S], M Message] interface {
		signatures.Signer[M, *Signature[GE, S]]
		Variant() VR
	}

	// Verifier validates Schnorr signatures against public keys.
	// It embeds the base Verifier interface and provides access to the variant.
	Verifier[VR Variant[GE, S, M], GE GroupElement[GE, S], S Scalar[S], M Message] interface {
		signatures.Verifier[*PublicKey[GE, S], M, *Signature[GE, S]]
		Variant() VR
	}

	// Scheme is the complete Schnorr signature scheme combining key generation,
	// signing, and verification. Different variants implement this interface
	// to provide variant-specific behavior while maintaining a consistent API.
	Scheme[
		VR Variant[GE, S, M], GE GroupElement[GE, S], S Scalar[S], M Message,
		KG KeyGenerator[GE, S], SG Signer[VR, GE, S, M], VF Verifier[VR, GE, S, M],
	] interface {
		signatures.Scheme[*PrivateKey[GE, S], *PublicKey[GE, S], M, *Signature[GE, S], KG, SG, VF]
		Variant() VR
	}
)

// Variant defines variant-specific behavior for a Schnorr signature scheme.
// Different variants (BIP-340, Mina, etc.) implement this interface to customize:
//   - Nonce generation (deterministic vs random, parity constraints)
//   - Challenge computation (hash function, input ordering, domain separation)
//   - Response calculation (s = k + ex vs s = k - ex)
//   - Signature serialization format
type Variant[GE GroupElement[GE, S], S Scalar[S], M Message] interface {
	// Type returns the variant identifier (e.g., "bip340", "mina").
	Type() VariantType

	// HashFunc returns the hash function constructor used for challenge computation.
	HashFunc() func() hash.Hash

	// ComputeNonceCommitment generates the nonce k and commitment R = k·G.
	// The implementation may use deterministic derivation (BIP-340, Mina)
	// or random sampling, and may enforce parity constraints on R.
	ComputeNonceCommitment() (GE, S, error)

	// ComputeChallenge computes the Fiat-Shamir challenge e = H(R || P || m).
	// The exact hash function, input ordering, and domain separation vary by variant.
	ComputeChallenge(nonceCommitment GE, publicKeyValue GE, message M) (S, error)

	// ComputeResponse computes the signature response s from the private key,
	// nonce, and challenge. Typically s = k + e·x or s = k - e·x.
	ComputeResponse(privateKeyValue, nonce, challenge S) (S, error)

	// SerializeSignature encodes the signature to bytes in variant-specific format.
	SerializeSignature(signature *Signature[GE, S]) ([]byte, error)
}

// Message is the type constraint for messages that can be signed.
type Message signatures.Message

// NewPublicKey creates a Schnorr public key from an elliptic curve point.
// The point must be non-nil, not the identity element, and torsion-free
// (in the prime-order subgroup) to be valid.
func NewPublicKey[PKV GroupElement[PKV, S], S Scalar[S]](value PKV) (*PublicKey[PKV, S], error) {
	if utils.IsNil(value) {
		return nil, ErrInvalidArgument.WithMessage("value is nil")
	}
	if value.IsOpIdentity() {
		return nil, ErrFailed.WithMessage("value is identity")
	}
	if !value.IsTorsionFree() {
		return nil, ErrFailed.WithMessage("value is not torsion free")
	}
	return &PublicKey[PKV, S]{
		PublicKeyTrait: signatures.PublicKeyTrait[PKV, S]{
			V: value,
		},
	}, nil
}

// PublicKey represents a Schnorr public key as an elliptic curve point P = x·G,
// where x is the corresponding private key and G is the group generator.
type PublicKey[PKV GroupElement[PKV, S], S Scalar[S]] struct {
	signatures.PublicKeyTrait[PKV, S]
}

// publicKeyDTO is the CBOR serialization format for public keys.
type publicKeyDTO[PKV GroupElement[PKV, S], S Scalar[S]] struct {
	PK PKV `cbor:"publicKey"`
}

// Equal returns true if two public keys represent the same curve point.
func (pk *PublicKey[PKV, S]) Equal(other *PublicKey[PKV, S]) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return pk.PublicKeyTrait.Equal(&other.PublicKeyTrait)
}

// Clone returns a deep copy of the public key.
func (pk *PublicKey[PKV, S]) Clone() *PublicKey[PKV, S] {
	if pk == nil {
		return nil
	}
	return &PublicKey[PKV, S]{PublicKeyTrait: *pk.PublicKeyTrait.Clone()}
}

// MarshalCBOR serializes the public key to CBOR format.
func (pk *PublicKey[PKV, S]) MarshalCBOR() ([]byte, error) {
	dto := &publicKeyDTO[PKV, S]{
		PK: pk.V,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to marshal schnorrlike PublicKey")
	}
	return data, nil
}

// UnmarshalCBOR deserializes a public key from CBOR format.
func (pk *PublicKey[PKV, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*publicKeyDTO[PKV, S]](data)
	if err != nil {
		return err
	}
	pk2, err := NewPublicKey(dto.PK)
	if err != nil {
		return err
	}
	*pk = *pk2
	return nil
}

// NewPrivateKey creates a Schnorr private key from a scalar value.
// The scalar must be non-zero and the corresponding public key must be provided.
// The public key should satisfy P = x·G where x is the private key scalar.
func NewPrivateKey[PKV GroupElement[PKV, SKV], SKV Scalar[SKV]](value SKV, publicKey *PublicKey[PKV, SKV]) (*PrivateKey[PKV, SKV], error) {
	if utils.IsNil(value) {
		return nil, ErrInvalidArgument.WithMessage("value is nil")
	}
	if value.IsOpIdentity() {
		return nil, ErrFailed.WithMessage("value is identity")
	}
	if publicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("publicKey is nil")
	}
	return &PrivateKey[PKV, SKV]{
		PrivateKeyTrait: signatures.PrivateKeyTrait[PKV, SKV]{
			V:              value,
			PublicKeyTrait: publicKey.PublicKeyTrait,
		},
	}, nil
}

// PrivateKey represents a Schnorr private key as a scalar x in [1, n-1],
// where n is the group order. The corresponding public key is P = x·G.
type PrivateKey[PKV GroupElement[PKV, SKV], SKV Scalar[SKV]] struct {
	signatures.PrivateKeyTrait[PKV, SKV]
}

// PublicKey returns the public key corresponding to this private key.
func (sk *PrivateKey[PKV, SKV]) PublicKey() *PublicKey[PKV, SKV] {
	return &PublicKey[PKV, SKV]{PublicKeyTrait: sk.PublicKeyTrait}
}

// Name returns the signature scheme name ("SchnorrLike").
func (sk *PrivateKey[PKV, SKV]) Name() signatures.Name {
	return Name
}

// Equal returns true if two private keys have the same scalar value.
func (sk *PrivateKey[PKV, SKV]) Equal(other *PrivateKey[PKV, SKV]) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return sk.Name() == other.Name() && sk.PrivateKeyTrait.Equal(&other.PrivateKeyTrait)
}

// Clone returns a deep copy of the private key.
func (sk *PrivateKey[PKV, SKV]) Clone() *PrivateKey[PKV, SKV] {
	if sk == nil {
		return nil
	}
	return &PrivateKey[PKV, SKV]{
		PrivateKeyTrait: *sk.PrivateKeyTrait.Clone(),
	}
}

// NewSignature creates a Schnorr signature from its components.
// A signature consists of:
//   - e: the challenge scalar (may be nil for some variants like Mina)
//   - r: the nonce commitment point R = k·G
//   - s: the response scalar s = k ± e·x
//
// At least one of e or r must be provided, as both are needed for verification
// (e can be recomputed from R, P, and m).
func NewSignature[GE GroupElement[GE, S], S Scalar[S]](e S, r GE, s S) (*Signature[GE, S], error) {
	if utils.IsNil(s) {
		return nil, ErrInvalidArgument.WithMessage("s is nil")
	}
	if utils.IsNil(r) && utils.IsNil(e) {
		return nil, ErrInvalidArgument.WithMessage("r and e can't both be nil")
	}
	return &Signature[GE, S]{
		E: e,
		R: r,
		S: s,
	}, nil
}

// Signature represents a Schnorr signature with three components:
//   - E: the Fiat-Shamir challenge e = H(R || P || m)
//   - R: the nonce commitment R = k·G
//   - S: the response s = k + e·x (or k - e·x for some variants)
//
// Some variants (like Mina) don't store E explicitly as it can be recomputed.
// The serialized format varies by variant (typically just R.x and S).
type Signature[GE GroupElement[GE, S], S Scalar[S]] struct {
	E S
	R GE
	S S
}

// Equal returns true if two signatures have identical E, R, and S values.
func (sig *Signature[GE, S]) Equal(other *Signature[GE, S]) bool {
	if sig == nil || other == nil {
		return sig == other
	}
	return sig.E.Equal(other.E) && sig.R.Equal(other.R) && sig.S.Equal(other.S)
}

// Clone returns a deep copy of the signature.
func (sig *Signature[GE, S]) Clone() *Signature[GE, S] {
	if sig == nil {
		return nil
	}
	return &Signature[GE, S]{
		E: sig.E.Clone(),
		R: sig.R.Clone(),
		S: sig.S.Clone(),
	}
}

// HashCode returns a hash code for the signature, useful for hash-based collections.
func (sig *Signature[GE, S]) HashCode() base.HashCode {
	return sig.E.HashCode() ^ sig.R.HashCode() ^ sig.S.HashCode()
}

// KeyGeneratorTrait provides common key generation logic for Schnorr schemes.
// It generates key pairs by sampling a random non-zero scalar x and computing P = x·G.
type KeyGeneratorTrait[GE GroupElement[GE, S], S Scalar[S]] struct {
	Grp Group[GE, S]   // The elliptic curve group
	SF  ScalarField[S] // The scalar field (integers mod group order)
}

// Generate creates a new Schnorr key pair using randomness from prng.
// The private key is a random scalar x in [1, n-1], and the public key is P = x·G.
func (kg *KeyGeneratorTrait[GE, S]) Generate(prng io.Reader) (*PrivateKey[GE, S], *PublicKey[GE, S], error) {
	if prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("prng is nil")
	}
	sc, err := algebrautils.RandomNonIdentity(kg.SF, prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("scalar")
	}
	pkv := kg.Grp.ScalarBaseOp(sc)
	pk, err := NewPublicKey(pkv)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("public key")
	}
	sk, err := NewPrivateKey(sc, pk)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("private key")
	}
	return sk, pk, nil
}

// SignerTrait provides common signing logic for Schnorr schemes.
// It implements the standard Schnorr signing algorithm using variant-specific
// nonce generation, challenge computation, and response calculation.
type SignerTrait[VR Variant[GE, S, M], GE GroupElement[GE, S], S Scalar[S], M Message] struct {
	Sk       *PrivateKey[GE, S]                                         // The signing private key
	V        VR                                                         // The Schnorr variant for algorithm customization
	Verifier signatures.Verifier[*PublicKey[GE, S], M, *Signature[GE, S]] // Verifier for signature self-check
}

// Sign creates a Schnorr signature on the given message.
// The signing process:
//  1. Generate nonce k and commitment R = k·G (via variant)
//  2. Compute challenge e = H(R || P || m) (via variant)
//  3. Compute response s = k + e·x (via variant)
//  4. Verify the signature before returning (defense in depth)
//
// The signature verification step protects against fault attacks that might
// produce invalid signatures leaking information about the private key.
func (sg *SignerTrait[VR, GE, S, M]) Sign(message M) (*Signature[GE, S], error) {
	R, k, err := sg.V.ComputeNonceCommitment()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("R")
	}
	e, err := sg.V.ComputeChallenge(R, sg.Sk.PublicKey().Value(), message)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("e")
	}
	s, err := sg.V.ComputeResponse(sg.Sk.Value(), k, e)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not compute response")
	}
	sigma := &Signature[GE, S]{
		E: e,
		R: R,
		S: s,
	}

	if err := sg.Verifier.Verify(sigma, sg.Sk.PublicKey(), message); err != nil {
		return nil, errs2.Wrap(err).WithMessage("signature verification failed")
	}
	return sigma, nil
}

// Variant returns the Schnorr variant used by this signer.
func (sg *SignerTrait[VR, GE, S, M]) Variant() VR {
	return sg.V
}

// VerifierTrait provides common verification logic for Schnorr schemes.
// It implements signature verification using the standard Schnorr equation:
// s·G = R + e·P (or s·G = R - e·P when ResponseOperatorIsNegative is true).
type VerifierTrait[VR Variant[GE, S, M], GE GroupElement[GE, S], S Scalar[S], M Message] struct {
	V                          VR              // The Schnorr variant for challenge computation
	ChallengePublicKey         *PublicKey[GE, S] // Optional override for partial signature verification
	ResponseOperatorIsNegative bool            // If true, uses s·G = R - e·P instead of s·G = R + e·P
}

// Variant returns the Schnorr variant used by this verifier.
func (v *VerifierTrait[VR, GE, S, M]) Variant() VR {
	return v.V
}

// Verify checks that a signature is valid for a message under a public key.
// The verification equation is: s·G = R + e·P (or R - e·P if ResponseOperatorIsNegative).
//
// For threshold/partial signatures, ChallengePublicKey can be set to use a
// different public key for challenge computation than for the verification equation.
func (v *VerifierTrait[VR, GE, S, M]) Verify(sigma *Signature[GE, S], publicKey *PublicKey[GE, S], message M) error {
	if publicKey == nil {
		return ErrInvalidArgument.WithMessage("publicKey is nil")
	}
	if publicKey.Value().IsOpIdentity() {
		return ErrInvalidArgument.WithMessage("publicKey is identity")
	}
	challengeR := sigma.R
	challengePublicKey := publicKey
	if v.ChallengePublicKey != nil {
		challengePublicKey = v.ChallengePublicKey
	}
	e, err := v.V.ComputeChallenge(challengeR, challengePublicKey.V, message)
	if err != nil {
		return errs2.Wrap(err).WithMessage("e")
	}
	// If sigma.E is provided, verify it matches the computed challenge
	// (Mina signatures don't store E, so this may be nil)
	if !utils.IsNil(sigma.E) && !sigma.E.Equal(e) {
		return ErrFailed.WithMessage("e")
	}
	generator := publicKey.Group().Generator()
	rhsOperand := publicKey.Value().ScalarOp(e)
	if v.ResponseOperatorIsNegative {
		rhsOperand = rhsOperand.OpInv()
	}
	right := sigma.R.Op(rhsOperand)
	left := generator.ScalarOp(sigma.S)
	if !left.Equal(right) {
		return ErrVerificationFailed.WithMessage("signature verification failed")
	}
	return nil
}

// BatchVerify verifies multiple signatures in sequence.
// This is a naive implementation that verifies each signature individually.
// Some variants (like BIP-340) provide optimized batch verification.
func (v *VerifierTrait[VR, GE, S, M]) BatchVerify(signatures []*Signature[GE, S], publicKeys []*PublicKey[GE, S], messages []M) error {
	if len(signatures) != len(publicKeys) || len(signatures) != len(messages) {
		return ErrFailed.WithMessage("mismatched lengths")
	}
	for i := range signatures {
		if err := v.Verify(signatures[i], publicKeys[i], messages[i]); err != nil {
			return errs2.Wrap(err).WithMessage("batch verification failed")
		}
	}
	return nil
}

func _[GE GroupElement[GE, S], S Scalar[S]]() {
	var (
		_ signatures.PublicKey[*PublicKey[GE, S]]   = (*PublicKey[GE, S])(nil)
		_ signatures.PrivateKey[*PrivateKey[GE, S]] = (*PrivateKey[GE, S])(nil)
		_ signatures.Signature[*Signature[GE, S]]   = (*Signature[GE, S])(nil)
	)
}
