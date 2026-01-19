// Package bls implements BLS (Boneh-Lynn-Shacham) digital signatures as specified in
// draft-irtf-cfrg-bls-signature-06.
//
// BLS signatures are built on pairing-friendly elliptic curves and support signature aggregation,
// where multiple signatures can be combined into a single compact signature while maintaining
// cryptographic security. This implementation supports the BLS12-381 curve family.
//
// The package provides three signature schemes for rogue key attack prevention:
//   - Basic: requires all messages in an aggregate to be distinct
//   - Message Augmentation: prepends the public key to each message before signing
//   - Proof of Possession (POP): requires signers to prove knowledge of their secret key
//
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html
package bls

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

const (
	// Name is the canonical identifier for this signature scheme.
	Name signatures.Name = "BLS"

	// Basic is a rogue key prevention algorithm that protects against rogue key attacks by
	// requiring all messages in an aggregate signature to be distinct.
	// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-3.1
	Basic RogueKeyPreventionAlgorithm = 1

	// MessageAugmentation is a rogue key prevention algorithm where signatures are computed
	// over the concatenation of the public key and message (pk || msg). This ensures messages
	// signed by different keys are inherently distinct, preventing rogue key attacks without
	// additional validation.
	// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-3.2
	MessageAugmentation RogueKeyPreventionAlgorithm = 2

	// POP (Proof of Possession) is a rogue key prevention algorithm where signers must
	// provide a proof demonstrating knowledge of their secret key. This enables the optimised
	// FastAggregateVerify algorithm for verifying multiple signatures on identical messages.
	// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-3.3
	POP RogueKeyPreventionAlgorithm = 3

	// ShortKey indicates the minimal-pubkey-size variant where public keys are points on
	// the G1 curve (48 bytes compressed) and signatures are points on G2 (96 bytes compressed).
	// This variant is preferred when public keys are transmitted more frequently than signatures.
	ShortKey Variant = 1

	// LongKey indicates the minimal-signature-size variant where public keys are points on
	// the G2 curve (96 bytes compressed) and signatures are points on G1 (48 bytes compressed).
	// This variant is preferred when signatures are transmitted more frequently than public keys.
	LongKey Variant = 2
)

// RogueKeyPreventionAlgorithm specifies the scheme used to prevent rogue key attacks in
// BLS signature aggregation. A rogue key attack occurs when an adversary creates a malicious
// public key that cancels out honest signers' contributions in an aggregate signature.
type RogueKeyPreventionAlgorithm int

// Variant specifies whether to use minimal public key size (ShortKey) or minimal signature
// size (LongKey). The choice determines which curve subgroup is used for keys vs signatures.
type Variant int

// Message is the type alias for message bytes to be signed or verified.
type Message = []byte

// CipherSuite defines the cryptographic parameters for a BLS signature scheme instance.
// It specifies the curve family and domain separation tags (DSTs) for hash-to-curve operations.
//
// Domain separation tags ensure that hash outputs for different purposes (signing, POP proofs)
// and different curve subgroups remain cryptographically independent. The tag format follows:
// "BLS_SIG_<curve>_<hash>_<map>_<variant>_" for signatures and
// "BLS_POP_<curve>_<hash>_<map>_<variant>_" for proof of possession.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-4.2
type CipherSuite struct {
	FamilyName                      string
	DstSignatureBasicInTwistedGroup string
	DstSignatureAugInTwistedGroup   string
	DstSignaturePopInTwistedGroup   string
	DstPopProofInTwistedGroup       string
	DstSignatureBasicInSourceGroup  string
	DstSignatureAugInSourceGroup    string
	DstSignaturePopInSourceGroup    string
	DstPopProofInSourceGroup        string
}

// GetDst returns the domain separation tag for signing operations based on the rogue key
// prevention algorithm and key/signature variant. The DST is used in hash-to-curve operations
// to ensure cryptographic domain separation between different signature schemes.
func (c *CipherSuite) GetDst(alg RogueKeyPreventionAlgorithm, variant Variant) (string, error) {
	switch alg {
	case Basic:
		if variant == ShortKey {
			return (c.DstSignatureBasicInTwistedGroup), nil
		}
		return (c.DstSignatureBasicInSourceGroup), nil
	case MessageAugmentation:
		if variant == ShortKey {
			return (c.DstSignatureAugInTwistedGroup), nil
		}
		return (c.DstSignatureAugInSourceGroup), nil
	case POP:
		if variant == ShortKey {
			return (c.DstSignaturePopInTwistedGroup), nil
		}
		return (c.DstSignaturePopInSourceGroup), nil
	default:
		return "", ErrNotSupported.WithMessage("algorithm type %v not implemented", alg)
	}
}

// GetPopDst returns the domain separation tag for proof of possession operations.
// Note: POP proofs hash the public key to the opposite subgroup from where the key lives,
// hence ShortKey (keys in G1) uses SourceGroup DST (hashing to G1 for POP proof).
func (c *CipherSuite) GetPopDst(variant Variant) string {
	if variant == ShortKey {
		return c.DstPopProofInSourceGroup
	}
	return c.DstPopProofInTwistedGroup
}

// BLS12381CipherSuite returns the standard ciphersuite for BLS12-381 curve.
// It uses SHA-256 for hashing and the simplified SWU map for hash-to-curve.
//
// The ciphersuite identifiers follow the format specified in:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-4.2
func BLS12381CipherSuite() *CipherSuite {
	return &CipherSuite{
		FamilyName: bls12381.FamilyName,
		// Domain separation tag for basic signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.1
		DstSignatureBasicInTwistedGroup: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
		// Domain separation tag for basic signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.2
		DstSignatureAugInTwistedGroup: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
		// Domain separation tag for proof of possession signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
		DstSignaturePopInTwistedGroup: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
		// Domain separation tag for proof of possession proofs
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
		DstPopProofInTwistedGroup: "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
		// Domain separation tag for basic signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.1
		DstSignatureBasicInSourceGroup: "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_",
		// Domain separation tag for basic signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.2
		DstSignatureAugInSourceGroup: "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_",
		// Domain separation tag for proof of possession signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
		DstSignaturePopInSourceGroup: "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_",
		// Domain separation tag for proof of possession proofs
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
		DstPopProofInSourceGroup: "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_",
	}
}

// RogueKeyPreventionAlgorithmIsSupported returns true if the given algorithm is one of
// the three supported rogue key prevention schemes: Basic, MessageAugmentation, or POP.
func RogueKeyPreventionAlgorithmIsSupported(alg RogueKeyPreventionAlgorithm) bool {
	return alg == Basic || alg == MessageAugmentation || alg == POP
}

// NewPublicKey creates a PublicKey from an elliptic curve point.
// The point must be a valid, non-identity element in the correct prime-order subgroup.
//
// Security: Validates that the point is not the identity element and is torsion-free
// (lies in the prime-order subgroup). This prevents invalid key attacks.
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.5
func NewPublicKey[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](v PK) (*PublicKey[PK, PKFE, Sig, SigFE, E, S], error) {
	if v.IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("cannot create public key from identity point")
	}
	if !v.IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("cannot create public key from torsion point")
	}
	return &PublicKey[PK, PKFE, Sig, SigFE, E, S]{
		PublicKeyTrait: signatures.PublicKeyTrait[PK, S]{V: v},
	}, nil
}

// NewPublicKeyFromBytes deserializes a PublicKey from its compressed byte representation.
// The input is validated to ensure it represents a valid curve point in the correct subgroup.
func NewPublicKeyFromBytes[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](subGroup curves.PairingFriendlyCurve[PK, PKFE, Sig, SigFE, E, S], input []byte) (*PublicKey[PK, PKFE, Sig, SigFE, E, S], error) {
	v, err := subGroup.FromBytes(input)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create public key from bytes")
	}
	return NewPublicKey(v)
}

// PublicKey represents a BLS public key as a point on a pairing-friendly elliptic curve.
// The public key is computed as pk = sk * G, where sk is the secret key scalar and G is
// the generator of the chosen subgroup (G1 for ShortKey variant, G2 for LongKey).
//
// Public keys can be aggregated via elliptic curve point addition to form aggregate
// public keys for multi-signature verification.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.4
type PublicKey[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	signatures.PublicKeyTrait[PK, S]
}

// Group returns the elliptic curve subgroup that this public key belongs to.
func (pk *PublicKey[P1, F1, P2, F2, E, S]) Group() curves.PairingFriendlyCurve[P1, F1, P2, F2, E, S] {
	group, ok := pk.V.Structure().(curves.PairingFriendlyCurve[P1, F1, P2, F2, E, S])
	if !ok {
		panic(ErrNotSupported.WithMessage("public key value does not implement curves.Curve interface"))
	}
	return group
}

// Name returns the signature scheme identifier ("BLS").
func (*PublicKey[P1, F1, P2, F2, E, S]) Name() signatures.Name {
	return Name
}

// Clone returns a deep copy of the public key.
func (pk *PublicKey[P1, F1, P2, F2, E, S]) Clone() *PublicKey[P1, F1, P2, F2, E, S] {
	if pk == nil {
		return nil
	}
	return &PublicKey[P1, F1, P2, F2, E, S]{PublicKeyTrait: *pk.PublicKeyTrait.Clone()}
}

// Equal returns true if both public keys represent the same curve point.
func (pk *PublicKey[P1, F1, P2, F2, E, S]) Equal(other *PublicKey[P1, F1, P2, F2, E, S]) bool {
	return pk != nil && other != nil && pk.PublicKeyTrait.Equal(&other.PublicKeyTrait)
}

// HashCode returns a hash of the public key for use in hash-based data structures.
func (pk *PublicKey[P1, F1, P2, F2, E, S]) HashCode() base.HashCode {
	return pk.PublicKeyTrait.HashCode()
}

// Bytes returns the compressed serialisation of the public key.
// For ShortKey variant (G1): 48 bytes. For LongKey variant (G2): 96 bytes.
func (pk *PublicKey[P1, F1, P2, F2, E, S]) Bytes() []byte {
	if pk == nil {
		return nil
	}
	return pk.Value().ToCompressed()
}

// IsShort returns true if this is a minimal-pubkey-size key (residing in G1).
func (pk *PublicKey[P1, F1, P2, F2, E, S]) IsShort() bool {
	return pk.Value().InSourceGroup()
}

// TryAdd aggregates this public key with another by elliptic curve point addition.
// The result can be used as an aggregate public key for verifying aggregate signatures.
// Returns an error if other is nil, the identity element, or not in the correct subgroup.
func (pk *PublicKey[P1, F1, P2, F2, E, S]) TryAdd(other *PublicKey[P1, F1, P2, F2, E, S]) (*PublicKey[P1, F1, P2, F2, E, S], error) {
	if other == nil {
		return nil, ErrInvalidArgument.WithMessage("cannot add nil public key")
	}
	if other.Value().IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("cannot add identity public key")
	}
	if !other.Value().IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("cannot add public key with torsion point")
	}
	return &PublicKey[P1, F1, P2, F2, E, S]{
		PublicKeyTrait: signatures.PublicKeyTrait[P1, S]{V: pk.Value().Add(other.Value())},
	}, nil
}

// NewPrivateKey creates a PrivateKey from a scalar value and computes the corresponding public key.
// The scalar must be non-zero and in the range [1, r-1] where r is the subgroup order.
//
// The public key is derived as pk = sk * G (SkToPk operation in the spec).
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.4
func NewPrivateKey[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](subGroup curves.PairingFriendlyCurve[PK, PKFE, Sig, SigFE, E, S], v S) (*PrivateKey[PK, PKFE, Sig, SigFE, E, S], error) {
	if v.IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("cannot create private key from identity scalar")
	}
	publicKeyValue := subGroup.ScalarBaseMul(v)
	return &PrivateKey[PK, PKFE, Sig, SigFE, E, S]{
		PrivateKeyTrait: signatures.PrivateKeyTrait[PK, S]{
			V: v,
			PublicKeyTrait: signatures.PublicKeyTrait[PK, S]{
				V: publicKeyValue,
			},
		},
	}, nil
}

// NewPrivateKeyFromBytes deserializes a PrivateKey from its byte representation.
// The input is interpreted as a big-endian integer and validated to be non-zero.
func NewPrivateKeyFromBytes[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](subGroup curves.PairingFriendlyCurve[PK, PKFE, Sig, SigFE, E, S], input []byte) (*PrivateKey[PK, PKFE, Sig, SigFE, E, S], error) {
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](subGroup.ScalarStructure())
	v, err := sf.FromBytes(input)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create private key from bytes")
	}
	return NewPrivateKey(subGroup, v)
}

// PrivateKey represents a BLS secret key as a scalar in the prime field Fr.
// The secret key sk is an integer in [1, r-1] where r is the order of the subgroups G1 and G2.
//
// Security: Private keys must be generated using a cryptographically secure random source
// and protected against side-channel attacks. The KeyGen algorithm uses HKDF for secure
// key derivation from random input keying material.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.3
type PrivateKey[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	signatures.PrivateKeyTrait[PK, S]
}

// Name returns the signature scheme identifier ("BLS").
func (*PrivateKey[PK, PKFE, Sig, SigFE, E, S]) Name() signatures.Name {
	return Name
}

// Group returns the elliptic curve associated with this private key's public key.
func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) Group() curves.Curve[PK, PKFE, S] {
	group, ok := sk.V.Structure().(curves.Curve[PK, PKFE, S])
	if !ok {
		panic(ErrNotSupported.WithMessage("private key value does not implement curves.Curve interface"))
	}
	return group
}

// PublicKey returns the public key corresponding to this private key.
// The public key is computed as pk = sk * G during key creation.
func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) PublicKey() *PublicKey[PK, PKFE, Sig, SigFE, E, S] {
	return &PublicKey[PK, PKFE, Sig, SigFE, E, S]{PublicKeyTrait: sk.PublicKeyTrait}
}

// Clone returns a deep copy of the private key.
func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) Clone() *PrivateKey[PK, PKFE, Sig, SigFE, E, S] {
	if sk == nil {
		return nil
	}
	return &PrivateKey[PK, PKFE, Sig, SigFE, E, S]{PrivateKeyTrait: *sk.PrivateKeyTrait.Clone()}
}

// Equal returns true if both private keys have the same scalar value.
func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) Equal(other *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return sk.PrivateKeyTrait.Equal(&other.PrivateKeyTrait)
}

// Bytes returns the little-endian byte representation of the secret key scalar.
// The output is 32 bytes for BLS12-381.
func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) Bytes() []byte {
	if sk == nil {
		return nil
	}
	return sliceutils.Reversed(sk.Value().Bytes())
}

// NewSignature creates a Signature from an elliptic curve point, optionally with a proof of possession.
// The point must be a valid, non-identity element in the correct prime-order subgroup.
//
// Security: Validates subgroup membership to prevent attacks exploiting small subgroup elements.
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.5
func NewSignature[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](v Sig, pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) (*Signature[Sig, SigFE, PK, PKFE, E, S], error) {
	if v.IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("cannot create signature from identity point")
	}
	if !v.IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("cannot create signature from torsion point")
	}
	return &Signature[Sig, SigFE, PK, PKFE, E, S]{
		v:   v,
		pop: pop,
	}, nil
}

// NewSignatureFromBytes deserializes a Signature from its compressed byte representation.
// The input is validated to ensure it represents a valid curve point in the correct subgroup.
func NewSignatureFromBytes[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](subGroup curves.PairingFriendlyCurve[Sig, SigFE, PK, PKFE, E, S], input []byte, pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) (*Signature[Sig, SigFE, PK, PKFE, E, S], error) {
	if subGroup == nil {
		return nil, ErrInvalidArgument.WithMessage("subgroup cannot be nil")
	}
	v, err := subGroup.FromBytes(input)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create signature from bytes")
	}
	return NewSignature(v, pop)
}

// Signature represents a BLS signature as a point on a pairing-friendly elliptic curve.
// The signature is computed as sig = sk * H(m), where sk is the secret key and H(m) is
// the hash-to-curve output for message m.
//
// Signatures can be aggregated via elliptic curve point addition. When using the POP scheme,
// signatures may include an attached proof of possession.
//
// Verification uses the pairing equation: e(pk, H(m)) = e(G, sig)
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.6
type Signature[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	v   Sig
	pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]
}

// Value returns the underlying curve point of the signature.
func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) Value() Sig {
	return sig.v
}

// Bytes returns the compressed serialisation of the signature.
// For ShortKey variant (sig in G2): 96 bytes. For LongKey variant (sig in G1): 48 bytes.
func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) Bytes() []byte {
	return sig.v.ToCompressed()
}

// IsLong returns true if this is a minimal-signature-size signature (residing in G1).
func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) IsLong() bool {
	return !sig.v.InSourceGroup()
}

// Pop returns the attached proof of possession, or nil if none is attached.
// Only signatures created with the POP rogue key prevention algorithm have attached proofs.
func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) Pop() *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S] {
	if sig == nil {
		return nil
	}
	return sig.pop
}

// TryAdd aggregates this signature with another by elliptic curve point addition.
// If both signatures have proofs of possession, those are also aggregated.
// Returns an error if other is nil, the identity element, or not in the correct subgroup.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.8
func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) TryAdd(other *Signature[Sig, SigFE, PK, PKFE, E, S]) (*Signature[Sig, SigFE, PK, PKFE, E, S], error) {
	if other == nil {
		return nil, ErrInvalidArgument.WithMessage("cannot add nil signature with proof of possession")
	}
	if other.v.IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("cannot add identity signature")
	}
	if !other.v.IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("cannot add signature with torsion point")
	}
	out := &Signature[Sig, SigFE, PK, PKFE, E, S]{v: sig.v.Add(other.v)}
	if sig.pop == nil && other.pop == nil {
		return out, nil
	}
	popAgg, err := sig.pop.TryAdd(other.pop)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not add proofs of possession in signature with proof of possession")
	}
	out.pop = popAgg
	return out, nil
}

// Equal returns true if both signatures represent the same curve point and have equal POPs.
func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) Equal(other *Signature[Sig, SigFE, PK, PKFE, E, S]) bool {
	return sig != nil && other != nil && sig.v.Equal(other.v) && sig.pop.Equal(other.pop)
}

// Clone returns a deep copy of the signature including any attached proof of possession.
func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) Clone() *Signature[Sig, SigFE, PK, PKFE, E, S] {
	return &Signature[Sig, SigFE, PK, PKFE, E, S]{
		v:   sig.v.Clone(),
		pop: sig.pop.Clone(),
	}
}

// HashCode returns a hash of the signature for use in hash-based data structures.
func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) HashCode() base.HashCode {
	return sig.v.HashCode()
}

// NewProofOfPossession creates a ProofOfPossession from an elliptic curve point.
// A proof of possession is a signature on the public key itself, demonstrating that
// the signer knows the corresponding secret key.
//
// The proof is generated as: pop = sk * H(pk) where H hashes to the signature subgroup
// using a distinct domain separation tag from regular signatures.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-3.3.2
func NewProofOfPossession[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](v Sig) (*ProofOfPossession[Sig, SigFE, PK, PKFE, E, S], error) {
	if v.IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("cannot create proof of possession from identity signature")
	}
	if !v.IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("cannot create proof of possession from signature with torsion point")
	}
	sig, err := NewSignature(v, nil)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create proof of possession from signature")
	}
	return &ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]{
		Signature: *sig,
	}, nil
}

// NewProofOfPossessionFromBytes deserializes a ProofOfPossession from its compressed byte representation.
// The input is validated to ensure it represents a valid curve point in the correct subgroup.
func NewProofOfPossessionFromBytes[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](subGroup curves.PairingFriendlyCurve[Sig, SigFE, PK, PKFE, E, S], input []byte) (*ProofOfPossession[Sig, SigFE, PK, PKFE, E, S], error) {
	if subGroup == nil {
		return nil, ErrInvalidArgument.WithMessage("subgroup cannot be nil")
	}
	v, err := subGroup.FromBytes(input)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create proof of possession from bytes")
	}
	pop, err := NewProofOfPossession(v)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create proof of possession from signature")
	}
	return pop, nil
}

// ProofOfPossession is a cryptographic proof that the holder of a public key knows
// the corresponding secret key. It prevents rogue key attacks in signature aggregation
// by requiring each participant to prove key ownership before their signatures are aggregated.
//
// The proof is verified using: e(pk, H(pk)) = e(G, pop)
// where H uses a domain separation tag distinct from signature generation.
//
// Proofs can be aggregated when verifying multiple signatures on the same message,
// enabling the efficient FastAggregateVerify algorithm.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-3.3
type ProofOfPossession[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	Signature[Sig, SigFE, PK, PKFE, E, S]
}

// Bytes returns the compressed serialisation of the proof of possession.
func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) Bytes() []byte {
	if pop == nil {
		return nil
	}
	return pop.Signature.Bytes()
}

// Value returns the underlying curve point of the proof.
func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) Value() Sig {
	return pop.Signature.Value()
}

// Equal returns true if both proofs represent the same curve point.
func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) Equal(other *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) bool {
	if pop == nil || other == nil {
		return pop == other
	}
	return pop.Signature.Equal(&other.Signature)
}

// Clone returns a deep copy of the proof of possession.
func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) Clone() *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S] {
	if pop == nil {
		return nil
	}
	return &ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]{Signature: *pop.Signature.Clone()}
}

// TryAdd aggregates this proof of possession with another by elliptic curve point addition.
// Used when aggregating signatures that each have attached proofs.
func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) TryAdd(other *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) (*ProofOfPossession[Sig, SigFE, PK, PKFE, E, S], error) {
	if other == nil {
		return nil, ErrInvalidArgument.WithMessage("cannot add nil proof of possession")
	}
	v, err := pop.Signature.TryAdd(&other.Signature)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not add signatures in proof of possession")
	}
	return &ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]{
		Signature: *v,
	}, nil
}

// HashCode returns a hash of the proof for use in hash-based data structures.
func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) HashCode() base.HashCode {
	return pop.Signature.HashCode()
}

// AggregateAll combines multiple BLS elements (public keys, signatures, or proofs) into a single
// aggregate element via elliptic curve point addition.
//
// For public keys: aggregate_pk = pk_1 + pk_2 + ... + pk_n
// For signatures: aggregate_sig = sig_1 + sig_2 + ... + sig_n
//
// The aggregation is homomorphic, enabling efficient batch verification of multiple signatures.
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.8
func AggregateAll[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, ET, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, ET, S], SGFE algebra.FieldElement[SGFE],
	ET algebra.MultiplicativeGroupElement[ET], S algebra.PrimeFieldElement[S],
	Xs ~[]X, X interface {
		TryAdd(other X) (X, error)
	},
](xs Xs) (X, error) {
	if len(xs) == 0 {
		return *new(X), ErrInvalidArgument.WithMessage("cannot aggregate empty slice of elements")
	}
	result, err := iterutils.ReduceOrError(
		slices.Values(xs[1:]),
		xs[0],
		func(acc X, pk X) (X, error) {
			aggregated, err := acc.TryAdd(pk)
			if err != nil {
				return *new(X), errs2.Wrap(err).WithMessage("could not aggregate public keys")
			}
			return aggregated, nil
		})
	if err != nil {
		return *new(X), errs2.Wrap(err).WithMessage("failed to aggregate BLS elements")
	}
	return result, nil
}
