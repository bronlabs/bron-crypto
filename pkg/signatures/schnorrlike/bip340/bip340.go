// Package bip340 implements BIP-340 Schnorr signatures for Bitcoin.
//
// BIP-340 defines a Schnorr signature scheme over the secp256k1 curve with
// specific design choices optimized for Bitcoin:
//
// # Key Features
//
//   - X-only public keys: Only the x-coordinate is used (32 bytes vs 33 compressed)
//   - Even y-coordinate constraint: R and P are implicitly lifted to have even y
//   - Tagged hashing: Domain-separated SHA-256 for aux, nonce, and challenge
//   - Deterministic nonce: k derived from private key, message, and auxiliary randomness
//
// # Signature Format
//
// A BIP-340 signature is 64 bytes: (R.x || s) where:
//   - R.x: 32-byte x-coordinate of the nonce commitment
//   - s: 32-byte response scalar
//
// # Security Properties
//
// The auxiliary randomness input protects against:
//   - Differential fault attacks
//   - Differential power analysis
//   - Nonce reuse with same message but different auxiliary data
//
// # Batch Verification
//
// BIP-340 supports efficient batch verification using random linear combinations,
// providing significant speedups when verifying multiple signatures.
//
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
package bip340

import (
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

type (
	// Group is the secp256k1 elliptic curve used by BIP-340.
	Group = k256.Curve
	// GroupElement is a point on the secp256k1 curve.
	GroupElement = k256.Point
	// ScalarField is the field of integers modulo the secp256k1 group order.
	ScalarField = k256.ScalarField
	// Scalar is an element of the scalar field.
	Scalar = k256.Scalar

	// Message is a byte slice to be signed.
	Message = []byte
	// PublicKey is a BIP-340 public key (x-only, 32 bytes when serialized).
	PublicKey = schnorrlike.PublicKey[*GroupElement, *Scalar]
	// PrivateKey is a BIP-340 private key (32-byte scalar).
	PrivateKey = schnorrlike.PrivateKey[*GroupElement, *Scalar]
	// Signature is a BIP-340 signature (R.x || s, 64 bytes).
	Signature = schnorrlike.Signature[*GroupElement, *Scalar]
)

const (
	// AuxSizeBytes is the size of auxiliary randomness for nonce generation (32 bytes).
	// The aux data is XORed with the private key before hashing to derive the nonce.
	AuxSizeBytes int = 32
)

var (
	_ schnorrlike.Scheme[*Variant, *k256.Point, *k256.Scalar, Message, *KeyGenerator, *Signer, *Verifier] = (*Scheme)(nil)
	_ schnorrlike.Variant[*GroupElement, *Scalar, Message]                                                = (*Variant)(nil)
	_ schnorrlike.KeyGenerator[*GroupElement, *Scalar]                                                    = (*KeyGenerator)(nil)
	_ schnorrlike.Signer[*Variant, *GroupElement, *Scalar, Message]                                       = (*Signer)(nil)
	_ schnorrlike.Verifier[*Variant, *GroupElement, *Scalar, Message]

	_ tschnorr.MPCFriendlyScheme[*Variant, *GroupElement, *Scalar, Message, *KeyGenerator, *Signer, *Verifier] = (*Scheme)(nil)
	_ tschnorr.MPCFriendlyVariant[*GroupElement, *Scalar, Message]                                             = (*Variant)(nil)
)

// NewPublicKey creates a BIP-340 public key from a secp256k1 curve point.
// The point is validated to be non-identity and in the prime-order subgroup.
func NewPublicKey(point *GroupElement) (*PublicKey, error) {
	pk, err := schnorrlike.NewPublicKey(point)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create BIP340 public key")
	}
	return pk, nil
}

// NewPrivateKey creates a BIP-340 private key from a scalar.
// The scalar must be non-zero. The corresponding public key P = x·G is computed.
func NewPrivateKey(scalar *Scalar) (*PrivateKey, error) {
	if scalar == nil {
		return nil, ErrInvalidArgument.WithMessage("scalar is nil")
	}
	if scalar.IsZero() {
		return nil, ErrInvalidArgument.WithMessage("scalar is zero")
	}
	pkv := k256.NewCurve().ScalarBaseMul(scalar)
	pk, err := schnorrlike.NewPublicKey(pkv)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create public key")
	}
	sk, err := schnorrlike.NewPrivateKey(scalar, pk)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create BIP340 private key")
	}
	return sk, nil
}

// NewSchemeWithAux creates a BIP-340 scheme with explicit auxiliary randomness.
// The aux data is used in nonce derivation: k = H(d XOR H(aux) || P || m).
// Use this when you need deterministic signatures with known aux data.
func NewSchemeWithAux(aux [AuxSizeBytes]byte) *Scheme {
	return &Scheme{
		aux: aux,
	}
}

// NewScheme creates a BIP-340 scheme with random auxiliary data.
// The aux data is sampled from prng and used for nonce derivation.
// This provides protection against side-channel attacks.
func NewScheme(prng io.Reader) (*Scheme, error) {
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng is nil")
	}

	aux := [AuxSizeBytes]byte{}
	_, err := io.ReadFull(prng, aux[:])
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot generate nonce")
	}
	return &Scheme{
		aux: aux,
	}, nil
}

// Scheme implements the BIP-340 Schnorr signature scheme.
// It provides key generation, signing, and verification following BIP-340.
type Scheme struct {
	aux [AuxSizeBytes]byte // Auxiliary randomness for nonce derivation
}

// Name returns the signature scheme identifier ("SchnorrLike").
func (s Scheme) Name() signatures.Name {
	return schnorrlike.Name
}

// Variant returns the BIP-340 variant configuration for this scheme.
func (s *Scheme) Variant() *Variant {
	return &Variant{
		Aux: s.aux,
	}
}

// Keygen creates a key generator for BIP-340 key pairs.
func (s *Scheme) Keygen(opts ...KeyGeneratorOption) (*KeyGenerator, error) {
	out := &KeyGenerator{
		KeyGeneratorTrait: schnorrlike.KeyGeneratorTrait[*GroupElement, *Scalar]{
			Grp: k256.NewCurve(),
			SF:  k256.NewScalarField(),
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs2.Wrap(err).WithMessage("key generator option failed")
		}
	}
	return out, nil
}

// Signer creates a signer for producing BIP-340 signatures.
// The signer uses deterministic nonce derivation per BIP-340.
func (s *Scheme) Signer(privateKey *PrivateKey, opts ...SignerOption) (*Signer, error) {
	if privateKey == nil {
		return nil, ErrInvalidArgument.WithMessage("private key is nil")
	}
	variant := &Variant{
		Aux: s.aux,
		sk:  privateKey,
	}
	out := &Signer{
		sg: schnorrlike.SignerTrait[*Variant, *GroupElement, *Scalar, Message]{
			Sk: privateKey,
			V:  variant,
			Verifier: &Verifier{
				variant: variant,
			},
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs2.Wrap(err).WithMessage("signer option failed")
		}
	}
	return out, nil
}

// Verifier creates a verifier for validating BIP-340 signatures.
func (s *Scheme) Verifier(opts ...VerifierOption) (*Verifier, error) {
	out := &Verifier{
		variant: s.Variant(),
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs2.Wrap(err).WithMessage("verifier option failed")
		}
	}
	return out, nil
}

// PartialSignatureVerifier creates a verifier for threshold/partial signatures.
// In MPC signing, each party produces a partial signature that must be verified
// against their individual public key share rather than the aggregate public key.
func (s *Scheme) PartialSignatureVerifier(
	publicKey *PublicKey,
	opts ...signatures.VerifierOption[*Verifier, *PublicKey, Message, *Signature],
) (schnorrlike.Verifier[*Variant, *GroupElement, *Scalar, Message], error) {
	if publicKey == nil || publicKey.Value() == nil {
		return nil, ErrInvalidArgument.WithMessage("public key is nil or invalid")
	}
	verifier, err := s.Verifier(opts...)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("verifier creation failed")
	}
	verifier.challengePublicKey = publicKey
	return verifier, nil
}

// NewSignatureFromBytes deserializes a BIP-340 signature from 64 bytes.
// The format is (R.x || s) where R.x is the 32-byte x-coordinate
// and s is the 32-byte response scalar.
func NewSignatureFromBytes(input []byte) (*Signature, error) {
	if len(input) != 64 {
		return nil, ErrSerialization.WithMessage("invalid length")
	}

	r, err := decodePoint(input[:32])
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	s, err := k256.NewScalarField().FromBytes(input[32:])
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid signature")
	}
	return &Signature{
		R: r,
		S: s,
	}, nil
}

// KeyGeneratorOption configures key generation behavior.
type KeyGeneratorOption = signatures.KeyGeneratorOption[*KeyGenerator, *PrivateKey, *PublicKey]

// KeyGenerator creates BIP-340 key pairs.
type KeyGenerator struct {
	schnorrlike.KeyGeneratorTrait[*GroupElement, *Scalar]
}

// SignerOption configures signing behavior.
type SignerOption = signatures.SignerOption[*Signer, Message, *Signature]

// Signer produces BIP-340 signatures using deterministic nonce derivation.
type Signer struct {
	sg schnorrlike.SignerTrait[*Variant, *GroupElement, *Scalar, Message]
}

// Sign creates a BIP-340 signature on the message.
// The nonce is derived deterministically from the private key, message,
// and auxiliary randomness per BIP-340 specification.
func (s *Signer) Sign(message Message) (*Signature, error) {
	// ComputeNonceCommitment requires a message
	s.sg.V.msg = message
	sig, err := s.sg.Sign(message)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to sign message")
	}
	return sig, nil
}

// Variant returns the BIP-340 variant used by this signer.
func (s *Signer) Variant() *Variant {
	return s.sg.V
}

// VerifierOption configures verification behavior.
type VerifierOption = signatures.VerifierOption[*Verifier, *PublicKey, Message, *Signature]

// VerifyWithPRNG configures the verifier with a PRNG for batch verification.
// The PRNG is used to generate random coefficients for the batch equation.
func VerifyWithPRNG(prng io.Reader) VerifierOption {
	return func(v *Verifier) error {
		if prng == nil {
			return ErrInvalidArgument.WithMessage("prng is nil")
		}
		v.prng = prng
		return nil
	}
}

// Verifier validates BIP-340 signatures.
type Verifier struct {
	variant            *Variant   // BIP-340 variant configuration
	prng               io.Reader  // PRNG for batch verification
	challengePublicKey *PublicKey // Override for partial signature verification
}

// Variant returns the BIP-340 variant used by this verifier.
func (v *Verifier) Variant() *Variant {
	return v.variant
}

// Verify checks that a BIP-340 signature is valid for a message under a public key.
//
// The verification follows BIP-340 Section 4.2:
//  1. P = lift_x(pk) - lift public key to have even y
//  2. e = H(R.x || P || m) mod n - compute challenge
//  3. R' = s·G - e·P - compute expected nonce commitment
//  4. Verify R'.x = r and R' has even y
//
// Returns nil if valid, otherwise returns an error describing the failure.
func (v *Verifier) Verify(signature *Signature, publicKey *PublicKey, message Message) error {
	if publicKey == nil || publicKey.Value() == nil {
		return ErrInvalidArgument.WithMessage("curve not supported")
	}
	if signature == nil || signature.R == nil || signature.S == nil || signature.R.IsZero() || signature.S.IsZero() {
		return ErrVerificationFailed.WithMessage("some signature elements are nil/zero")
	}
	if publicKey.Value().IsOpIdentity() {
		return ErrVerificationFailed.WithMessage("public key is identity")
	}
	if !publicKey.Value().IsTorsionFree() {
		return ErrInvalidArgument.WithMessage("Public Key not in the prime subgroup")
	}

	challengePublicKeyValue := LiftX(publicKey.Value())
	if v.challengePublicKey != nil {
		// TODO: should this be lifted?
		challengePublicKeyValue = v.challengePublicKey.Value()
	}

	// 1. Let P = lift_x(int(pk)).
	// 2. (implicit) Let r = int(sig[0:32]); fail if r ≥ p.
	// 3. (implicit) Let s = int(sig[32:64]); fail if s ≥ n.
	bigP := LiftX(publicKey.Value())

	// 4. Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
	e, err := v.variant.ComputeChallenge(signature.R, challengePublicKeyValue, message)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot create challenge scalar")
	}

	if signature.E != nil && !signature.E.Equal(e) {
		return ErrFailed.WithMessage("incompatible signature")
	}

	// 5. Let R = s⋅G - e⋅P.
	bigR := k256.NewCurve().ScalarBaseMul(signature.S).Sub(bigP.ScalarMul(e))

	// 6. Fail if is_infinite(R).
	if bigR.IsZero() {
		return ErrVerificationFailed.WithMessage("signature is invalid")
	}

	// 7. Fail if not has_even_y(R).
	ry, err := bigR.AffineY()
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot compute y coordinate")
	}
	if ry.IsOdd() {
		return ErrVerificationFailed.WithMessage("signature is invalid")
	}

	// 8. Fail if x(R) ≠ r.
	sigRx, err := signature.R.AffineX()
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot compute x coordinate")
	}
	rx, err := bigR.AffineX()
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot compute x coordinate")
	}
	if !sigRx.Equal(rx) {
		return ErrVerificationFailed.WithMessage("signature is invalid")
	}
	return nil
}

// BatchVerify efficiently verifies multiple BIP-340 signatures using random linear combinations.
//
// The batch equation is: (s1 + a2·s2 + ... + au·su)·G = R1 + a2·R2 + ... + au·Ru + e1·P1 + (a2·e2)·P2 + ... + (au·eu)·Pu
//
// This is more efficient than individual verification when verifying many signatures,
// as it requires only one multi-scalar multiplication instead of u separate ones.
//
// The verifier must be initialized with a PRNG using VerifyWithPRNG option.
// The random coefficients a2...au prevent an attacker from constructing signatures
// that pass batch verification but fail individual verification.
func (v *Verifier) BatchVerify(signatures []*Signature, publicKeys []*PublicKey, messages []Message, prng io.Reader) error {
	if v.prng == nil {
		return ErrInvalidArgument.WithMessage("batch verification requires a prng. Initialise the verifier with the prng option")
	}
	if len(publicKeys) != len(signatures) || len(signatures) != len(messages) || len(signatures) == 0 {
		return ErrInvalidArgument.WithMessage("length of publickeys, messages and signatures must be equal and greater than zero")
	}
	if sliceutils.Any(publicKeys, func(pk *PublicKey) bool {
		return pk == nil || pk.Value() == nil || pk.Value().IsOpIdentity() || pk.Value().IsOpIdentity()
	}) {

		return ErrInvalidArgument.WithMessage("some public keys are nil or identity")
	}
	curve := k256.NewCurve()
	sf := k256.NewScalarField()
	var err error
	// 1. Generate u-1 random integers a2...u in the range 1...n-1.
	a := make([]*k256.Scalar, len(signatures))
	a[0] = sf.One()
	for i := 1; i < len(signatures); i++ {
		a[i], err = algebrautils.RandomNonIdentity(sf, prng)
		if err != nil {
			return errs2.Wrap(err).WithMessage("cannot generate random scalar for i=%d", i)
		}
	}

	// For i = 1 .. u:
	left := sf.Zero()
	ae := make([]*k256.Scalar, len(signatures))
	bigR := make([]*k256.Point, len(signatures))
	bigP := make([]*k256.Point, len(signatures))
	for i, sig := range signatures {
		// 2. Let P_i = lift_x(int(pki))
		// 3. (implicit) Let r_i = int(sigi[0:32]); fail if ri ≥ p.
		// 4. (implicit) Let s_i = int(sigi[32:64]); fail if si ≥ n.
		bigP[i] = LiftX(publicKeys[i].Value())

		// 5. Let ei = int(hashBIP0340/challenge(bytes(r_i) || bytes(P_i) || mi)) mod n.
		e, err := v.variant.ComputeChallenge(sig.R, publicKeys[i].V, messages[i])
		if err != nil {
			return errs2.Wrap(err).WithMessage("invalid signature")
		}

		// 6. Let Ri = lift_x(ri); fail if lift_x(ri) fails.
		bigR[i] = LiftX(signatures[i].R)

		ae[i] = a[i].Mul(e)
		left = left.Add(a[i].Mul(sig.S))
	}

	// 7. Fail if (s1 + a2s2 + ... + ausu)⋅G ≠ R1 + a2⋅R2 + ... + au⋅Ru + e1⋅P1 + (a2e2)⋅P2 + ... + (aueu)⋅Pu.
	rightA, err := curve.MultiScalarMul(a, bigR)
	if err != nil {
		return errs2.Wrap(err).WithMessage("failed to multiply scalars and points")
	}
	rightB, err := curve.MultiScalarMul(ae, bigP)
	if err != nil {
		return errs2.Wrap(err).WithMessage("failed to multiply scalars and points")
	}
	right := rightA.Add(rightB)
	if !curve.Generator().ScalarMul(left).Equal(right) {
		return ErrVerificationFailed.WithMessage("signature is invalid")
	}

	// Return success iff no failure occurred before reaching this point.
	return nil
}

// LiftX converts a point to have an even y-coordinate per BIP-340.
// If p.y is odd, returns -p (which has even y). Otherwise returns p unchanged.
// This is used to convert x-only public keys and R values to full curve points.
func LiftX(p *k256.Point) *k256.Point {
	if p.IsZero() {
		return p
	}

	py, err := p.AffineY()
	if err != nil {
		panic("this should never happen")
	}
	if py.IsOdd() {
		return p.Neg()
	}
	return p
}

// SerializeSignature encodes a BIP-340 signature to 64 bytes: (R.x || s).
// The R point is encoded as its 32-byte x-coordinate (x-only encoding).
func SerializeSignature(signature *Signature) ([]byte, error) {
	if signature == nil || signature.R == nil || signature.S == nil {
		return nil, ErrInvalidArgument.WithMessage("signature is nil")
	}
	return slices.Concat(signature.R.ToCompressed()[1:], signature.S.Bytes()), nil
}

// NewPublicKeyFromBytes deserializes a BIP-340 public key from 32 bytes (x-only).
// The y-coordinate is implicitly even per the BIP-340 lift_x operation.
func NewPublicKeyFromBytes(input []byte) (*PublicKey, error) {
	p, err := decodePoint(input)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot decode point")
	}
	pk, err := NewPublicKey(p)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create public key")
	}
	return pk, nil
}

// SerializePublicKey encodes a BIP-340 public key to 32 bytes (x-only).
// Only the x-coordinate is serialized; y is implicitly even.
func SerializePublicKey(publicKey *PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("public key is nil")
	}
	return publicKey.Value().ToCompressed()[1:], nil
}

// encodePoint serializes a point to 32 bytes (x-coordinate only).
func encodePoint(p *k256.Point) []byte {
	return p.ToCompressed()[1:]
}

// decodePoint deserializes a 32-byte x-coordinate to a curve point.
// The point is reconstructed with even y-coordinate (0x02 prefix).
func decodePoint(data []byte) (*k256.Point, error) {
	curve := k256.NewCurve()
	p, err := curve.FromCompressed(slices.Concat([]byte{0x02}, data))
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot decode point")
	}

	return p, nil
}
