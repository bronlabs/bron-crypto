// Package mina implements Schnorr signatures for the Mina Protocol.
//
// Mina uses a Schnorr signature scheme over the Pallas curve (part of the Pasta
// curve cycle) with the Poseidon hash function for challenge computation.
// This signature scheme is used for transaction signing in the Mina blockchain.
//
// # Key Differences from Standard Schnorr
//
//   - Curve: Pallas (part of Pasta cycle, ~255-bit prime field)
//   - Hash: Poseidon algebraic hash over the base field
//   - Message format: ROInput (structured field elements and bits)
//   - Byte order: Little-endian for field elements
//   - Nonce derivation: Deterministic using Blake2b (legacy mode)
//   - R encoding: Only x-coordinate with implicit even y
//
// # Signature Format
//
// A Mina signature is 64 bytes: (R.x || s) in little-endian, where:
//   - R.x: 32-byte x-coordinate of the nonce commitment
//   - s: 32-byte response scalar
//
// The y-coordinate of R is always even (parity 0), enforced during signing.
//
// # Network IDs
//
// Mina uses network-specific prefixes for domain separation:
//   - MainNet: "MinaSignatureMainnet"
//   - TestNet: "CodaSignature*******"
//
// References:
//   - Mina Protocol: https://minaprotocol.com
//   - o1js implementation: https://github.com/o1-labs/o1js
package mina

import (
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

type (
	// Group is the Pallas elliptic curve used by Mina.
	Group = pasta.PallasCurve
	// GroupElement is a point on the Pallas curve.
	GroupElement = pasta.PallasPoint
	// ScalarField is the field of integers modulo the Pallas group order.
	ScalarField = pasta.PallasScalarField
	// Scalar is an element of the scalar field.
	Scalar = pasta.PallasScalar

	// Message is an ROInput containing structured field elements and bits.
	Message = ROInput
	// PublicKey is a Mina public key (Pallas curve point).
	PublicKey = schnorrlike.PublicKey[*GroupElement, *Scalar]
	// PrivateKey is a Mina private key (scalar).
	PrivateKey = schnorrlike.PrivateKey[*GroupElement, *Scalar]
	// Signature is a Mina signature (R.x || s, 64 bytes little-endian).
	Signature = schnorrlike.Signature[*GroupElement, *Scalar]
)

var (
	hashFunc = poseidon.NewLegacyHash
	group    = pasta.NewPallasCurve()
	sf       = pasta.NewPallasScalarField()

	// SignatureSize is the size of a serialised Mina signature (64 bytes).
	SignatureSize = group.ElementSize() + sf.ElementSize()
	// PublicKeySize is the size of a serialised Mina public key (32 bytes).
	PublicKeySize = group.ElementSize()
	// PrivateKeySize is the size of a Mina private key (32 bytes).
	PrivateKeySize = sf.ElementSize()

	_ schnorrlike.Scheme[*Variant, *GroupElement, *Scalar, *Message, *KeyGenerator, *Signer, *Verifier]         = (*Scheme)(nil)
	_ tschnorr.MPCFriendlyScheme[*Variant, *GroupElement, *Scalar, *Message, *KeyGenerator, *Signer, *Verifier] = (*Scheme)(nil)
)

// NewPublicKey creates a Mina public key from a Pallas curve point.
func NewPublicKey(point *GroupElement) (*PublicKey, error) {
	pk, err := schnorrlike.NewPublicKey(point)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create Mina public key")
	}
	return pk, nil
}

// NewPrivateKey creates a Mina private key from a scalar.
// The scalar must be non-zero. The corresponding public key P = x·G is computed.
func NewPrivateKey(scalar *Scalar) (*PrivateKey, error) {
	if scalar == nil {
		return nil, ErrInvalidArgument.WithMessage("scalar is nil")
	}
	if scalar.IsZero() {
		return nil, ErrInvalidArgument.WithMessage("scalar is zero")
	}
	pkv := group.ScalarBaseMul(scalar)
	pk, err := schnorrlike.NewPublicKey(pkv)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create public key")
	}
	sk, err := schnorrlike.NewPrivateKey(scalar, pk)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create Mina private key")
	}
	return sk, nil
}

// NewScheme creates a Mina signature scheme with deterministic nonce derivation.
// The nonce is derived from the private key, public key, and network ID using
// Blake2b, following the legacy Mina/o1js implementation.
func NewScheme(nid NetworkId, privateKey *PrivateKey) (*Scheme, error) {
	vr, err := NewDeterministicVariant(nid, privateKey)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create variant")
	}
	return &Scheme{
		vr: vr,
	}, nil
}

// NewRandomisedScheme creates a Mina signature scheme with random nonce generation.
// This is typically used for MPC/threshold signing where nonces are generated
// collaboratively rather than deterministically.
func NewRandomisedScheme(nid NetworkId, prng io.Reader) (*Scheme, error) {
	vr, err := NewRandomisedVariant(nid, prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create variant")
	}
	return &Scheme{
		vr: vr,
	}, nil
}

// Scheme implements the Mina Schnorr signature scheme.
// It supports both deterministic and randomised nonce generation modes.
type Scheme struct {
	vr *Variant
}

// Name returns the signature scheme identifier ("SchnorrLike").
func (*Scheme) Name() signatures.Name {
	return schnorrlike.Name
}

// Variant returns the Mina variant configuration for this scheme.
func (s *Scheme) Variant() *Variant {
	return s.vr
}

// Keygen creates a key generator for Mina key pairs.
func (s *Scheme) Keygen(opts ...KeyGeneratorOption) (*KeyGenerator, error) {
	kg := &KeyGenerator{
		schnorrlike.KeyGeneratorTrait[*GroupElement, *Scalar]{
			Grp: group,
			SF:  sf,
		},
	}
	for _, opt := range opts {
		if err := opt(kg); err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to apply key generator option")
		}
	}
	return kg, nil
}

// Signer creates a signer for producing Mina signatures.
func (s *Scheme) Signer(privateKey *PrivateKey, opts ...SignerOption) (*Signer, error) {
	if privateKey == nil {
		return nil, ErrInvalidArgument.WithMessage("private key is nil")
	}
	verifier, err := s.Verifier()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("verifier creation failed")
	}
	signer := &Signer{
		schnorrlike.SignerTrait[*Variant, *GroupElement, *Scalar, *Message]{
			Sk:       privateKey,
			V:        s.vr,
			Verifier: verifier,
		},
	}
	for _, opt := range opts {
		if err := opt(signer); err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to apply signer option")
		}
	}
	return signer, nil
}

// Verifier creates a verifier for validating Mina signatures.
func (s *Scheme) Verifier(opts ...VerifierOption) (*Verifier, error) {
	verifier := &Verifier{
		VerifierTrait: schnorrlike.VerifierTrait[*Variant, *GroupElement, *Scalar, *Message]{
			V:                          s.vr,
			ResponseOperatorIsNegative: false,
		},
	}
	for _, opt := range opts {
		if err := opt(verifier); err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to apply verifier option")
		}
	}
	return verifier, nil
}

// PartialSignatureVerifier creates a verifier for threshold/partial signatures.
func (s *Scheme) PartialSignatureVerifier(publicKey *PublicKey, opts ...signatures.VerifierOption[*Verifier, *PublicKey, *Message, *Signature]) (schnorrlike.Verifier[*Variant, *GroupElement, *Scalar, *Message], error) {
	if publicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("public key is nil")
	}
	verifier, err := s.Verifier(opts...)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("verifier creation failed")
	}
	verifier.ChallengePublicKey = publicKey
	return verifier, nil
}

// KeyGeneratorOption configures key generation behaviour.
type KeyGeneratorOption = signatures.KeyGeneratorOption[*KeyGenerator, *PrivateKey, *PublicKey]

// KeyGenerator creates Mina key pairs on the Pallas curve.
type KeyGenerator struct {
	schnorrlike.KeyGeneratorTrait[*GroupElement, *Scalar]
}

// SignerOption configures signing behaviour.
type SignerOption = signatures.SignerOption[*Signer, *Message, *Signature]

// Signer produces Mina signatures.
type Signer struct {
	schnorrlike.SignerTrait[*Variant, *GroupElement, *Scalar, *Message]
}

// Sign creates a Mina signature on the given message.
// The message is set on the variant before signing to enable deterministic
// nonce derivation that includes the message content.
func (s *Signer) Sign(message *Message) (*Signature, error) {
	// Set message on variant for deterministic nonce derivation
	s.V.msg = message
	sig, err := s.SignerTrait.Sign(message)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// VerifierOption configures verification behaviour.
type VerifierOption = signatures.VerifierOption[*Verifier, *PublicKey, *Message, *Signature]

// VerifyWithPRNG configures the verifier with a PRNG (for future batch verification).
func VerifyWithPRNG(prng io.Reader) VerifierOption {
	return func(v *Verifier) error {
		if prng == nil {
			return ErrInvalidArgument.WithMessage("prng is nil")
		}
		v.prng = prng
		return nil
	}
}

// Verifier validates Mina signatures.
type Verifier struct {
	schnorrlike.VerifierTrait[*Variant, *GroupElement, *Scalar, *Message]

	prng io.Reader // PRNG for future batch verification support
}

// SerializeSignature encodes a Mina signature to 64 bytes in little-endian format.
// The format is (R.x || s) where both components are in little-endian byte order.
// This matches the Mina/o1js serialisation convention.
func SerializeSignature(signature *Signature) ([]byte, error) {
	if signature == nil {
		return nil, ErrInvalidArgument.WithMessage("signature is nil")
	}
	// Mina uses LITTLE-ENDIAN for field elements
	rx, err := signature.R.AffineX()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to serialise signature")
	}

	// Convert R.x from big-endian to little-endian
	rxBytesBE := rx.Bytes()
	rxBytesLE := make([]byte, len(rxBytesBE))
	for i := range rxBytesBE {
		rxBytesLE[i] = rxBytesBE[len(rxBytesBE)-1-i]
	}

	// Convert S from big-endian to little-endian
	sBytesBE := signature.S.Bytes()
	sBytesLE := make([]byte, len(sBytesBE))
	for i := range sBytesBE {
		sBytesLE[i] = sBytesBE[len(sBytesBE)-1-i]
	}

	out := slices.Concat(rxBytesLE, sBytesLE)
	if len(out) != SignatureSize {
		return nil, ErrSerialization.WithMessage("invalid signature size. got :%d, need :%d", len(out), SignatureSize)
	}
	return out, nil
}

// DeserializeSignature parses a Mina signature from 64 bytes in little-endian format.
// The R point is reconstructed from its x-coordinate with even y-coordinate (parity 0).
// The challenge E is not stored and will be recomputed during verification.
func DeserializeSignature(input []byte) (*Signature, error) {
	if len(input) != SignatureSize {
		return nil, ErrSerialization.WithMessage("invalid signature size. got :%d, need :%d", len(input), SignatureSize)
	}

	rxBytesLE := input[:group.ElementSize()]
	sBytesLE := input[group.ElementSize():]

	// Mina uses LITTLE-ENDIAN for field elements
	// Convert R.x from little-endian to big-endian
	rxBytesBE := make([]byte, len(rxBytesLE))
	for i := range rxBytesLE {
		rxBytesBE[i] = rxBytesLE[len(rxBytesLE)-1-i]
	}

	// Parse R.x as a base field element
	rx, err := group.BaseField().FromBytes(rxBytesBE)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to parse R.x")
	}

	// Reconstruct R from x-coordinate
	// Mina signatures always have R with even y-coordinate (parity=0)
	R, err := group.FromAffineX(rx, false)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to reconstruct R from x-coordinate")
	}

	// Convert S from little-endian to big-endian
	sBytesBE := make([]byte, len(sBytesLE))
	for i := range sBytesLE {
		sBytesBE[i] = sBytesLE[len(sBytesLE)-1-i]
	}

	s, err := sf.FromBytes(sBytesBE)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create scalar from bytes")
	}

	return &Signature{
		R: R,
		S: s,
		// E is not stored in Mina signatures, it will be recomputed during verification
	}, nil
}
