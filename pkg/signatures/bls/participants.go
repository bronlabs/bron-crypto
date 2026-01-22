package bls

import (
	"encoding/hex"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

// KeyGeneratorOption is a functional option for configuring a KeyGenerator.
type KeyGeneratorOption[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] = signatures.KeyGeneratorOption[
	*KeyGenerator[PK, PKFE, SG, SGFE, E, S],
	*PrivateKey[PK, PKFE, SG, SGFE, E, S],
	*PublicKey[PK, PKFE, SG, SGFE, E, S],
]

// GenerateWithSeed returns a KeyGeneratorOption that uses the provided seed for
// deterministic key generation instead of random sampling.
//
// The seed must be at least as long as the scalar field element size (32 bytes for BLS12-381).
// Using the same seed will always produce the same key pair.
func GenerateWithSeed[PK curves.PairingFriendlyPoint[PK, FE, Sig, SigFE, E, S], FE algebra.FieldElement[FE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, FE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](seed []byte) KeyGeneratorOption[PK, FE, Sig, SigFE, E, S] {
	return func(kg *KeyGenerator[PK, FE, Sig, SigFE, E, S]) error {
		kg.seed = seed
		return nil
	}
}

// KeyGenerator generates BLS key pairs using the KeyGen algorithm from the specification.
// Key generation uses HKDF with SHA3-256 to derive secret keys from input keying material.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.3
type KeyGenerator[
	PK curves.PairingFriendlyPoint[PK, FE, Sig, SigFE, E, S], FE algebra.FieldElement[FE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, FE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	group curves.PairingFriendlyCurve[PK, FE, Sig, SigFE, E, S]
	seed  []byte
}

// GenerateWithSeed derives a BLS key pair from the provided input keying material (IKM).
// The IKM must be at least 32 bytes and should contain high-entropy random data.
//
// This implements the KeyGen algorithm:
//  1. Hash the salt to get initial HKDF salt
//  2. Use HKDF-Extract and HKDF-Expand to derive key material
//  3. Convert to scalar, re-hash salt if result is zero
//  4. Compute public key as sk * G
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.3
func (kg *KeyGenerator[PK, FE, Sig, SigFE, E, S]) GenerateWithSeed(ikm []byte) (*PrivateKey[PK, FE, Sig, SigFE, E, S], *PublicKey[PK, FE, Sig, SigFE, E, S], error) {
	skv, _, err := generateWithSeed(kg.group, ikm)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not generate key pair")
	}
	sk, err := NewPrivateKey(kg.group, skv)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create private key")
	}
	pk := sk.PublicKey()
	return sk, pk, nil
}

// Generate creates a new BLS key pair using random bytes from the provided reader.
// If a seed was previously set via GenerateWithSeed option, that seed is used instead.
//
// The prng should be a cryptographically secure random source (e.g., crypto/rand.Reader).
func (kg *KeyGenerator[PK, FE, Sig, SigFE, E, S]) Generate(prng io.Reader) (*PrivateKey[PK, FE, Sig, SigFE, E, S], *PublicKey[PK, FE, Sig, SigFE, E, S], error) {
	if kg.seed == nil {
		sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](kg.group.ScalarStructure())
		kg.seed = make([]byte, sf.ElementSize())
		if _, err := io.ReadFull(prng, kg.seed); err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not read from PRNG")
		}
	}
	return kg.GenerateWithSeed(kg.seed)
}

// SignerOption is a functional option for configuring a Signer.
type SignerOption[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] = signatures.SignerOption[
	*Signer[PK, PKFE, SG, SGFE, E, S],
	[]byte,
	*Signature[SG, SGFE, PK, PKFE, E, S],
]

// SignWithCustomDST returns a SignerOption that overrides the default domain separation tag
// for hash-to-curve operations. This allows interoperability with systems using non-standard DSTs.
//
// Warning: Using non-standard DSTs may break compatibility with other BLS implementations.
func SignWithCustomDST[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](dst string) SignerOption[PK, PKFE, SG, SGFE, E, S] {
	return func(s *Signer[PK, PKFE, SG, SGFE, E, S]) error {
		if dst == "" {
			return ErrInvalidArgument.WithMessage("domain separation tag cannot be empty")
		}
		s.dst = dst
		return nil
	}
}

// Signer produces BLS signatures using the CoreSign algorithm. The signing behaviour
// depends on the configured rogue key prevention algorithm:
//   - Basic: signs the message directly
//   - MessageAugmentation: signs pk || message
//   - POP: signs message and attaches a proof of possession
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.6
type Signer[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	privateKey        *PrivateKey[PK, PKFE, SG, SGFE, E, S]
	signatureSubGroup curves.PairingFriendlyCurve[SG, SGFE, PK, PKFE, E, S]
	rogueKeyAlg       RogueKeyPreventionAlgorithm
	cipherSuite       *CipherSuite
	variant           Variant

	dst string
}

// Sign creates a BLS signature on the given message.
// The signature is computed as: sig = sk * H(msg) where H is hash-to-curve.
//
// For MessageAugmentation scheme, the public key is prepended to the message.
// For POP scheme, a proof of possession is attached to the signature.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.6
func (s *Signer[PK, PKFE, SG, SGFE, E, S]) Sign(message []byte) (*Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if len(message) == 0 {
		return nil, ErrInvalidArgument.WithMessage("message cannot be nil")
	}

	var err error
	if s.dst == "" {
		s.dst, err = s.cipherSuite.GetDst(s.rogueKeyAlg, s.variant)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not get domain separation tag")
		}
	}
	pop := ProofOfPossession[SG, SGFE, PK, PKFE, E, S]{}
	switch s.rogueKeyAlg {
	// identical to coreSign: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-3.1-2
	case Basic:
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-sign
	case MessageAugmentation:
		// step 3.2.1.2 (namely, the pk || message portion)
		message, err = AugmentMessage(message, s.privateKey.PublicKey().Value())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not augment message")
		}
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
	case POP:
		popv, err := popProve(s.privateKey.Value(), s.privateKey.PublicKey().Value(), s.signatureSubGroup, s.cipherSuite.GetPopDst(s.variant))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not produce proof of possession")
		}
		pop.v = popv
	default:
		return nil, ErrNotSupported.WithMessage("rogue key prevention algorithm %d is not supported", s.rogueKeyAlg)
	}

	sgv, err := coreSign(s.signatureSubGroup, s.privateKey.Value(), message, s.dst)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sign")
	}
	out := &Signature[SG, SGFE, PK, PKFE, E, S]{v: sgv, pop: nil}
	if s.rogueKeyAlg == POP {
		out.pop = &pop
	}
	return out, nil
}

// AggregateSign creates a single aggregate signature over multiple messages using the same key.
// This is more efficient than signing each message individually and then aggregating.
//
// The resulting signature can be verified against the signer's public key and all messages.
func (s *Signer[PK, PKFE, SG, SGFE, E, S]) AggregateSign(messages ...Message) (*Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if len(messages) == 0 {
		return nil, ErrInvalidArgument.WithMessage("need at least one message to batch sign")
	}

	var err error
	if s.dst == "" {
		s.dst, err = s.cipherSuite.GetDst(s.rogueKeyAlg, s.variant)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not get domain separation tag")
		}
	}

	pop := ProofOfPossession[SG, SGFE, PK, PKFE, E, S]{}
	switch s.rogueKeyAlg {
	case Basic:
	case MessageAugmentation:
		for i, message := range messages {
			messages[i], err = AugmentMessage(message, s.privateKey.PublicKey().Value())
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("could not augment message")
			}
		}
	case POP:
		popv, err := popProve(s.privateKey.Value(), s.privateKey.PublicKey().Value(), s.signatureSubGroup, s.cipherSuite.GetPopDst(s.variant))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not produce proof of possession")
		}
		pop.v = popv
	default:
		return nil, ErrNotSupported.WithMessage("rogue key prevention algorithm %d is not supported", s.rogueKeyAlg)
	}

	sgv, err := coreAggregateSign(s.signatureSubGroup, s.privateKey.Value(), messages, s.dst)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sign")
	}
	out := &Signature[SG, SGFE, PK, PKFE, E, S]{v: sgv, pop: nil}
	if s.rogueKeyAlg == POP {
		out.pop = &pop
	}
	return out, nil
}

// BatchSign creates individual signatures for each message in parallel.
// Returns a slice of signatures, one per message, in the same order as the input.
//
// This is useful when you need separate signatures that can be independently verified
// or selectively aggregated later.
func (s *Signer[PK, PKFE, SG, SGFE, E, S]) BatchSign(messages ...Message) ([]*Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if len(messages) == 0 {
		return nil, ErrInvalidArgument.WithMessage("need at least one message to batch sign")
	}

	var err error
	if s.dst == "" {
		s.dst, err = s.cipherSuite.GetDst(s.rogueKeyAlg, s.variant)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not get domain separation tag")
		}
	}

	pop := ProofOfPossession[SG, SGFE, PK, PKFE, E, S]{}
	switch s.rogueKeyAlg {
	case Basic:
	case MessageAugmentation:
		for i, message := range messages {
			messages[i], err = AugmentMessage(message, s.privateKey.PublicKey().Value())
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("could not augment message")
			}
		}
	case POP:
		popv, err := popProve(s.privateKey.Value(), s.privateKey.PublicKey().Value(), s.signatureSubGroup, s.cipherSuite.GetPopDst(s.variant))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not produce proof of possession")
		}
		pop.v = popv
	default:
		return nil, ErrNotSupported.WithMessage("rogue key prevention algorithm %d is not supported", s.rogueKeyAlg)
	}

	batch := make([]*Signature[SG, SGFE, PK, PKFE, E, S], len(messages))

	batchValues, err := coreBatchSign(
		s.signatureSubGroup, s.privateKey.Value(), messages, s.dst,
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not batch sign")
	}

	for i, v := range batchValues {
		batch[i] = &Signature[SG, SGFE, PK, PKFE, E, S]{v: v, pop: nil}
		if s.rogueKeyAlg == POP {
			batch[i].pop = &pop
			continue
		}
	}

	return batch, nil
}

// VerifierOption is a functional option for configuring a Verifier.
type VerifierOption[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] = signatures.VerifierOption[
	*Verifier[PK, PKFE, SG, SGFE, E, S],
	*PublicKey[PK, PKFE, SG, SGFE, E, S],
	[]byte,
	*Signature[SG, SGFE, PK, PKFE, E, S],
]

// VerifyWithCustomDST returns a VerifierOption that overrides the default domain separation tag.
// The DST must match the one used during signing for verification to succeed.
//
// Warning: Using non-standard DSTs may break compatibility with other BLS implementations.
func VerifyWithCustomDST[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](dst string) VerifierOption[PK, PKFE, SG, SGFE, E, S] {
	return func(s *Verifier[PK, PKFE, SG, SGFE, E, S]) error {
		if dst == "" {
			return ErrInvalidArgument.WithMessage("domain separation tag cannot be empty")
		}
		s.dst = dst
		return nil
	}
}

// VerifyWithProofsOfPossession returns a VerifierOption that provides pre-validated proofs
// of possession for aggregate signature verification. This is required for AggregateVerify
// when using the POP rogue key prevention scheme.
//
// The number of proofs must match the number of public keys in the verification.
func VerifyWithProofsOfPossession[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](pops ...*ProofOfPossession[SG, SGFE, PK, PKFE, E, S]) VerifierOption[PK, PKFE, SG, SGFE, E, S] {
	return func(v *Verifier[PK, PKFE, SG, SGFE, E, S]) error {
		for i, pop := range pops {
			if pop == nil {
				return ErrInvalidArgument.WithMessage("proof of possession %d is nil", i)
			}
		}
		v.pops = pops
		return nil
	}
}

// Verifier validates BLS signatures using the CoreVerify algorithm.
// Verification uses the pairing equation to check: e(pk, H(m)) = e(G, sig)
//
// The verification behaviour depends on the rogue key prevention algorithm:
//   - Basic: verifies signature directly
//   - MessageAugmentation: reconstructs pk || message before verification
//   - POP: verifies attached proof of possession before signature verification
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.7
type Verifier[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	signatureSubGroup curves.PairingFriendlyCurve[SG, SGFE, PK, PKFE, E, S]
	rogueKeyAlg       RogueKeyPreventionAlgorithm
	cipherSuite       *CipherSuite
	variant           Variant

	pops []*ProofOfPossession[SG, SGFE, PK, PKFE, E, S]
	dst  string
}

// Verify validates a BLS signature against a public key and message.
//
// The verification uses an optimised pairing check: e(pk^-1, H(m)) * e(G, sig) = 1
// which reduces the number of Miller loop iterations.
//
// Security: Validates that both the public key and signature are valid non-identity
// points in their respective prime-order subgroups before performing verification.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.7
func (v *Verifier[PK, PKFE, SG, SGFE, E, S]) Verify(signature *Signature[SG, SGFE, PK, PKFE, E, S], publicKey *PublicKey[PK, PKFE, SG, SGFE, E, S], message Message) error {
	if len(message) == 0 {
		return ErrInvalidArgument.WithMessage("message cannot be nil")
	}
	if !publicKey.Value().IsTorsionFree() {
		return ErrInvalidSubGroup.WithMessage("public key is not torsion-free")
	}
	if publicKey.Value().IsOpIdentity() {
		return ErrInvalidArgument.WithMessage("public key is the identity element")
	}
	if !signature.Value().IsTorsionFree() {
		return ErrInvalidSubGroup.WithMessage("signature is not torsion-free")
	}
	if signature.Value().IsOpIdentity() {
		return ErrInvalidArgument.WithMessage("signature is the identity element")
	}

	var err error
	if v.dst == "" {
		v.dst, err = v.cipherSuite.GetDst(v.rogueKeyAlg, v.variant)
		if err != nil {
			return errs.Wrap(err).WithMessage("could not get domain separation tag")
		}
	}

	switch v.rogueKeyAlg {
	// identical to coreSign: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-3.1-2
	case Basic:
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-sign
	case MessageAugmentation:
		// step 3.2.1.2 (namely, the pk || message portion)
		message, err = AugmentMessage(message, publicKey.Value())
		if err != nil {
			return errs.Wrap(err).WithMessage("could not augment message")
		}
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
	case POP:
		pop := signature.Pop()
		if pop == nil {
			return ErrInvalidArgument.WithMessage("signature does not contain proof of possession")
		}
		if err := popVerify(publicKey.Value(), pop.v, v.signatureSubGroup, v.cipherSuite.GetPopDst(v.variant)); err != nil {
			return ErrVerificationFailed.WithMessage("could not verify proof of possession")
		}
	default:
		return ErrNotSupported.WithMessage("rogue key prevention algorithm %d is not supported", v.rogueKeyAlg)
	}
	if err := coreVerify(publicKey.Value(), message, signature.Value(), v.dst, v.signatureSubGroup); err != nil {
		return ErrVerificationFailed.WithMessage("could not verify signature")
	}
	return nil
}

// AggregateVerify validates an aggregate signature against multiple public keys and messages.
// The verification behaviour depends on the rogue key prevention algorithm:
//
//   - Basic: requires all messages to be distinct to prevent rogue key attacks
//   - MessageAugmentation: augments each message with its corresponding public key
//   - POP: requires valid proofs of possession for each public key (via VerifyWithProofsOfPossession)
//
// When all messages are identical and using the POP scheme, the optimised FastAggregateVerify
// algorithm is used, which aggregates public keys before verification.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.9
func (v *Verifier[PK, PKFE, SG, SGFE, E, S]) AggregateVerify(signature *Signature[SG, SGFE, PK, PKFE, E, S], publicKeys []*PublicKey[PK, PKFE, SG, SGFE, E, S], messages []Message) error {
	if len(publicKeys) != len(messages) {
		return ErrInvalidArgument.WithMessage("#public keys != #messages")
	}
	for i, publicKey := range publicKeys {
		if !publicKey.Value().IsTorsionFree() {
			return ErrInvalidSubGroup.WithMessage("public key %d is not torsion-free", i)
		}
		if publicKey.Value().IsOpIdentity() {
			return ErrInvalidArgument.WithMessage("public key %d is the identity element", i)
		}
	}
	if !signature.Value().IsTorsionFree() {
		return ErrInvalidSubGroup.WithMessage("signature is not torsion-free")
	}
	if signature.Value().IsOpIdentity() {
		return ErrInvalidArgument.WithMessage("signature is the identity element")
	}

	var err error
	if v.dst == "" {
		v.dst, err = v.cipherSuite.GetDst(v.rogueKeyAlg, v.variant)
		if err != nil {
			return errs.Wrap(err).WithMessage("could not get domain separation tag")
		}
	}

	switch v.rogueKeyAlg {
	// case 3.1.1
	case Basic:
		if len(v.pops) > 0 {
			return ErrInvalidArgument.WithMessage("nonzero number of pops when scheme is basic")
		}
		// step 3.1.1.1
		if !sliceutils.IsAllUnique(sliceutils.Map(messages, hex.EncodeToString)) {
			return ErrInvalidArgument.WithMessage("messages are not unique")
		}
	// case 3.3
	case POP:
		if len(publicKeys) != len(v.pops) {
			return ErrInvalidArgument.WithMessage("#publicKeys != #pops")
		}
		popDst := v.cipherSuite.GetPopDst(v.variant)
		for i, pop := range v.pops {
			if err := popVerify(publicKeys[i].Value(), pop.Value(), v.signatureSubGroup, popDst); err != nil {
				return ErrVerificationFailed.WithMessage("pop %d is invalid", i)
			}
		}
	// case 3.2.3 https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-aggregateverify-2
	case MessageAugmentation:
		if len(v.pops) > 0 {
			return ErrInvalidArgument.WithMessage("nonzero number of pops when scheme is message augmentation")
		}
		// step 3.2.3.1
		for i, publicKey := range publicKeys {
			// step 3.2.3.2
			augmentedMessage, err := AugmentMessage(messages[i], publicKey.Value())
			if err != nil {
				return errs.Wrap(err).WithMessage("could not augment message")
			}
			messages[i] = augmentedMessage
		}
	default:
		return ErrNotSupported.WithMessage("rogue key prevention scheme %d is not supported", v.rogueKeyAlg)
	}

	// FastAggregateVerify is a verification algorithm for the aggregate of multiple signatures on the same message. This function is faster than AggregateVerify.
	//
	// All public keys passed as arguments to this algorithm MUST have a corresponding proof of possession, and the result of evaluating PopVerify on each public key and its proof MUST be VALID. The caller is responsible for ensuring that this precondition is met. If it is violated, this scheme provides no security against aggregate signature forgery.
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-fastaggregateverify
	canRunFastAggregateVerify := (sliceutils.CountUnique(sliceutils.Map(messages, hex.EncodeToString)) == 1) && v.rogueKeyAlg == POP
	if canRunFastAggregateVerify {
		aggregatedPublicKey, err := AggregateAll[PK](publicKeys)
		if err != nil {
			return errs.Wrap(err).WithMessage("could not aggregate public keys")
		}
		if err := coreVerify(aggregatedPublicKey.Value(), messages[0], signature.Value(), v.dst, v.signatureSubGroup); err != nil {
			return ErrVerificationFailed.WithMessage("could not verify fast aggregate signature")
		}
		return nil
	} else {
		unwrappedPublicKeys := slices.Collect(iterutils.Map(slices.Values(publicKeys), func(pk *PublicKey[PK, PKFE, SG, SGFE, E, S]) PK {
			return pk.Value()
		}))
		if err := coreAggregateVerify(unwrappedPublicKeys, messages, signature.Value(), v.dst, v.signatureSubGroup); err != nil {
			return ErrVerificationFailed.WithMessage("could not verify aggregate signature")
		}
		return nil
	}
}
