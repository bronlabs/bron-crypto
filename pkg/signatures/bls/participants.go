package bls

import (
	"encoding/hex"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

type KeyGeneratorOption[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] = signatures.KeyGeneratorOption[
	*KeyGenerator[PK, PKFE, SG, SGFE, E, S],
	*PrivateKey[PK, PKFE, SG, SGFE, E, S],
	*PublicKey[PK, PKFE, SG, SGFE, E, S],
]

func GenerateWithSeed[PK curves.PairingFriendlyPoint[PK, FE, Sig, SigFE, E, S], FE algebra.FieldElement[FE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, FE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](seed []byte) KeyGeneratorOption[PK, FE, Sig, SigFE, E, S] {
	return func(kg *KeyGenerator[PK, FE, Sig, SigFE, E, S]) error {
		kg.seed = seed
		return nil
	}
}

type KeyGenerator[
	PK curves.PairingFriendlyPoint[PK, FE, Sig, SigFE, E, S], FE algebra.FieldElement[FE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, FE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	group curves.PairingFriendlyCurve[PK, FE, Sig, SigFE, E, S]
	seed  []byte
}

func (kg *KeyGenerator[PK, FE, Sig, SigFE, E, S]) GenerateWithSeed(ikm []byte) (*PrivateKey[PK, FE, Sig, SigFE, E, S], *PublicKey[PK, FE, Sig, SigFE, E, S], error) {
	skv, _, err := generateWithSeed(kg.group, ikm)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate key pair")
	}
	sk, err := NewPrivateKey(kg.group, skv)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create private key")
	}
	return sk, sk.PublicKey(), nil
}

func (kg *KeyGenerator[PK, FE, Sig, SigFE, E, S]) Generate(prng io.Reader) (*PrivateKey[PK, FE, Sig, SigFE, E, S], *PublicKey[PK, FE, Sig, SigFE, E, S], error) {
	if kg.seed == nil {
		sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](kg.group.ScalarStructure())
		kg.seed = make([]byte, sf.ElementSize())
		if _, err := io.ReadFull(prng, kg.seed); err != nil {
			return nil, nil, errs.WrapRandomSample(err, "could not read from PRNG")
		}
	}
	return kg.GenerateWithSeed(kg.seed)
}

type SignerOption[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] = signatures.SignerOption[
	*Signer[PK, PKFE, SG, SGFE, E, S],
	[]byte,
	*Signature[SG, SGFE, PK, PKFE, E, S],
]

func SignWithCustomDST[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](dst string) SignerOption[PK, PKFE, SG, SGFE, E, S] {
	return func(s *Signer[PK, PKFE, SG, SGFE, E, S]) error {
		if dst == "" {
			return errs.NewIsNil("domain separation tag cannot be empty")
		}
		s.dst = dst
		return nil
	}
}

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

func (s *Signer[PK, PKFE, SG, SGFE, E, S]) Sign(message []byte) (*Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if len(message) == 0 {
		return nil, errs.NewIsNil("message cannot be nil")
	}

	var err error
	if s.dst == "" {
		s.dst, err = s.cipherSuite.GetDst(s.rogueKeyAlg, s.variant)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not get domain separation tag")
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
			return nil, errs.WrapFailed(err, "could not augment message")
		}
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
	case POP:
		popv, err := popProve(s.privateKey.Value(), s.privateKey.PublicKey().Value(), s.signatureSubGroup, s.cipherSuite.GetPopDst(s.variant))
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce proof of possession")
		}
		pop.v = popv
	default:
		return nil, errs.NewType("rogue key prevention algorithm %d is not supported", s.rogueKeyAlg)
	}

	sgv, err := coreSign(s.signatureSubGroup, s.privateKey.Value(), message, s.dst)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not sign")
	}
	out := &Signature[SG, SGFE, PK, PKFE, E, S]{v: sgv}
	if s.rogueKeyAlg == POP {
		out.pop = &pop
	}
	return out, nil
}

func (s *Signer[PK, PKFE, SG, SGFE, E, S]) AggregateSign(messages ...Message) (*Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if len(messages) == 0 {
		return nil, errs.NewIsNil("need at least one message to batch sign")
	}

	var err error
	if s.dst == "" {
		s.dst, err = s.cipherSuite.GetDst(s.rogueKeyAlg, s.variant)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not get domain separation tag")
		}
	}

	pop := ProofOfPossession[SG, SGFE, PK, PKFE, E, S]{}
	switch s.rogueKeyAlg {
	case Basic:
	case MessageAugmentation:
		for i, message := range messages {
			messages[i], err = AugmentMessage(message, s.privateKey.PublicKey().Value())
			if err != nil {
				return nil, errs.WrapFailed(err, "could not augment message")
			}
		}
	case POP:
		popv, err := popProve(s.privateKey.Value(), s.privateKey.PublicKey().Value(), s.signatureSubGroup, s.cipherSuite.GetPopDst(s.variant))
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce proof of possession")
		}
		pop.v = popv
	default:
		return nil, errs.NewType("rogue key prevention algorithm %d is not supported", s.rogueKeyAlg)
	}

	sgv, err := coreAggregateSign(s.signatureSubGroup, s.privateKey.Value(), messages, s.dst)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not sign")
	}
	out := &Signature[SG, SGFE, PK, PKFE, E, S]{v: sgv}
	if s.rogueKeyAlg == POP {
		out.pop = &pop
	}
	return out, nil
}

func (s *Signer[PK, PKFE, SG, SGFE, E, S]) BatchSign(messages ...Message) ([]*Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if len(messages) == 0 {
		return nil, errs.NewIsNil("need at least one message to batch sign")
	}

	var err error
	if s.dst == "" {
		s.dst, err = s.cipherSuite.GetDst(s.rogueKeyAlg, s.variant)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not get domain separation tag")
		}
	}

	pop := ProofOfPossession[SG, SGFE, PK, PKFE, E, S]{}
	switch s.rogueKeyAlg {
	case Basic:
	case MessageAugmentation:
		for i, message := range messages {
			messages[i], err = AugmentMessage(message, s.privateKey.PublicKey().Value())
			if err != nil {
				return nil, errs.WrapFailed(err, "could not augment message")
			}
		}
	case POP:
		popv, err := popProve(s.privateKey.Value(), s.privateKey.PublicKey().Value(), s.signatureSubGroup, s.cipherSuite.GetPopDst(s.variant))
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce proof of possession")
		}
		pop.v = popv
	default:
		return nil, errs.NewType("rogue key prevention algorithm %d is not supported", s.rogueKeyAlg)
	}

	batch := make([]*Signature[SG, SGFE, PK, PKFE, E, S], len(messages))

	batchValues, err := coreBatchSign(
		s.signatureSubGroup, s.privateKey.Value(), messages, s.dst,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not batch sign")
	}

	for i, v := range batchValues {
		batch[i] = &Signature[SG, SGFE, PK, PKFE, E, S]{v: v}
		if s.rogueKeyAlg == POP {
			batch[i].pop = &pop
			continue
		}
	}

	return batch, nil
}

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

func VerifyWithCustomDST[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](dst string) VerifierOption[PK, PKFE, SG, SGFE, E, S] {
	return func(s *Verifier[PK, PKFE, SG, SGFE, E, S]) error {
		if dst == "" {
			return errs.NewIsNil("domain separation tag cannot be empty")
		}
		s.dst = dst
		return nil
	}
}

func VerifyWithProofsOfPossession[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](pops ...*ProofOfPossession[SG, SGFE, PK, PKFE, E, S]) VerifierOption[PK, PKFE, SG, SGFE, E, S] {
	return func(v *Verifier[PK, PKFE, SG, SGFE, E, S]) error {
		for i, pop := range pops {
			if pop == nil {
				return errs.NewIsNil("proof of possession %d is nil", i)
			}
		}
		v.pops = pops
		return nil
	}
}

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

// Verify implements the verification algorithm for all 3 schemes
// Basic: identical to core sign.
// Verify: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-verify
// POP: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
func (v *Verifier[PK, PKFE, SG, SGFE, E, S]) Verify(signature *Signature[SG, SGFE, PK, PKFE, E, S], publicKey *PublicKey[PK, PKFE, SG, SGFE, E, S], message Message) error {
	if len(message) == 0 {
		return errs.NewIsNil("message cannot be nil")
	}
	if !publicKey.Value().IsTorsionFree() {
		return errs.NewValue("public key is not torsion-free")
	}
	if publicKey.Value().IsOpIdentity() {
		return errs.NewValue("public key is the identity element")
	}
	if !signature.Value().IsTorsionFree() {
		return errs.NewValue("signature is not torsion-free")
	}
	if signature.Value().IsOpIdentity() {
		return errs.NewValue("signature is the identity element")
	}

	var err error
	if v.dst == "" {
		v.dst, err = v.cipherSuite.GetDst(v.rogueKeyAlg, v.variant)
		if err != nil {
			return errs.WrapFailed(err, "could not get domain separation tag")
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
			return errs.WrapFailed(err, "could not augment message")
		}
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
	case POP:
		pop := signature.Pop()
		if pop == nil {
			return errs.NewIsNil("signature does not contain proof of possession")
		}
		if err := popVerify(publicKey.Value(), pop.v, v.signatureSubGroup, v.cipherSuite.GetPopDst(v.variant)); err != nil {
			return errs.WrapVerification(err, "could not verify proof of possession")
		}
	default:
		return errs.NewType("rogue key prevention algorithm %d is not supported", v.rogueKeyAlg)
	}
	if err := coreVerify(publicKey.Value(), message, signature.Value(), v.dst, v.signatureSubGroup); err != nil {
		return errs.WrapVerification(err, "could not verify signature")
	}
	return nil
}

func (v *Verifier[PK, PKFE, SG, SGFE, E, S]) AggregateVerify(signature *Signature[SG, SGFE, PK, PKFE, E, S], publicKeys []*PublicKey[PK, PKFE, SG, SGFE, E, S], messages []Message) error {
	if len(publicKeys) != len(messages) {
		return errs.NewSize("#public keys != #messages")
	}
	for i, publicKey := range publicKeys {
		if !publicKey.Value().IsTorsionFree() {
			return errs.NewValue("public key %d is not torsion-free", i)
		}
		if publicKey.Value().IsOpIdentity() {
			return errs.NewValue("public key %d is the identity element", i)
		}
	}
	if !signature.Value().IsTorsionFree() {
		return errs.NewValue("signature is not torsion-free")
	}
	if signature.Value().IsOpIdentity() {
		return errs.NewValue("signature is the identity element")
	}

	var err error
	if v.dst == "" {
		v.dst, err = v.cipherSuite.GetDst(v.rogueKeyAlg, v.variant)
		if err != nil {
			return errs.WrapFailed(err, "could not get domain separation tag")
		}
	}

	switch v.rogueKeyAlg {
	// case 3.1.1
	case Basic:
		if len(v.pops) > 0 {
			return errs.NewSize("nonzero number of pops when scheme is basic")
		}
		// step 3.1.1.1
		if !sliceutils.IsAllUnique(sliceutils.Map(messages, hex.EncodeToString)) {
			return errs.NewMembership("messages are not unique")
		}
	// case 3.3
	case POP:
		if len(publicKeys) != len(v.pops) {
			return errs.NewSize("#publicKeys != #pops")
		}
		popDst := v.cipherSuite.GetPopDst(v.variant)
		for i, pop := range v.pops {
			if err := popVerify(publicKeys[i].Value(), pop.Value(), v.signatureSubGroup, popDst); err != nil {
				return errs.WrapVerification(err, "pop %d is invalid", i)
			}
		}
	// case 3.2.3 https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-aggregateverify-2
	case MessageAugmentation:
		if len(v.pops) > 0 {
			return errs.NewSize("nonzero number of pops when scheme is message augmentation")
		}
		// step 3.2.3.1
		for i, publicKey := range publicKeys {
			// step 3.2.3.2
			augmentedMessage, err := AugmentMessage(messages[i], publicKey.Value())
			if err != nil {
				return errs.WrapFailed(err, " could not augment message")
			}
			messages[i] = augmentedMessage
		}
	default:
		return errs.NewType("rogue key prevention scheme %d is not supported", v.variant)
	}

	// FastAggregateVerify is a verification algorithm for the aggregate of multiple signatures on the same message. This function is faster than AggregateVerify.
	//
	// All public keys passed as arguments to this algorithm MUST have a corresponding proof of possession, and the result of evaluating PopVerify on each public key and its proof MUST be VALID. The caller is responsible for ensuring that this precondition is met. If it is violated, this scheme provides no security against aggregate signature forgery.
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-fastaggregateverify
	canRunFastAggregateVerify := (sliceutils.CountUnique(sliceutils.Map(messages, hex.EncodeToString)) == 1) && v.rogueKeyAlg == POP
	if canRunFastAggregateVerify {
		aggregatedPublicKey, err := AggregateAll[PK](publicKeys)
		if err != nil {
			return errs.WrapFailed(err, "could not aggregate public keys")
		}
		if err := coreVerify(aggregatedPublicKey.Value(), messages[0], signature.Value(), v.dst, v.signatureSubGroup); err != nil {
			return errs.WrapVerification(err, "could not verify fast aggregate signature")
		}
		return nil
	} else {
		unwrappedPublicKeys := slices.Collect(iterutils.Map(slices.Values(publicKeys), func(pk *PublicKey[PK, PKFE, SG, SGFE, E, S]) PK {
			return pk.Value()
		}))
		if err := coreAggregateVerify(unwrappedPublicKeys, messages, signature.Value(), v.dst, v.signatureSubGroup); err != nil {
			return errs.WrapVerification(err, "could not verify aggregate signature")
		}
		return nil
	}
}

func _[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
]() {
	var (
		_ signatures.KeyGenerator[*PrivateKey[PK, PKFE, Sig, SigFE, E, S], *PublicKey[PK, PKFE, Sig, SigFE, E, S]] = (*KeyGenerator[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.KeyGenerator[*PrivateKey[Sig, SigFE, PK, PKFE, E, S], *PublicKey[Sig, SigFE, PK, PKFE, E, S]] = (*KeyGenerator[Sig, SigFE, PK, PKFE, E, S])(nil)

		_ signatures.BatchSigner[Message, *Signature[Sig, SigFE, PK, PKFE, E, S]] = (*Signer[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.BatchSigner[Message, *Signature[PK, PKFE, Sig, SigFE, E, S]] = (*Signer[Sig, SigFE, PK, PKFE, E, S])(nil)

		_ signatures.AggregateSigner[Message, *Signature[Sig, SigFE, PK, PKFE, E, S], *Signature[Sig, SigFE, PK, PKFE, E, S]] = (*Signer[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.AggregateSigner[Message, *Signature[PK, PKFE, Sig, SigFE, E, S], *Signature[PK, PKFE, Sig, SigFE, E, S]] = (*Signer[Sig, SigFE, PK, PKFE, E, S])(nil)

		_ signatures.Verifier[*PublicKey[PK, PKFE, Sig, SigFE, E, S], Message, *Signature[Sig, SigFE, PK, PKFE, E, S]] = (*Verifier[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.Verifier[*PublicKey[Sig, SigFE, PK, PKFE, E, S], Message, *Signature[PK, PKFE, Sig, SigFE, E, S]] = (*Verifier[Sig, SigFE, PK, PKFE, E, S])(nil)

		_ signatures.AggregateVerifier[*PublicKey[PK, PKFE, Sig, SigFE, E, S], Message, *Signature[Sig, SigFE, PK, PKFE, E, S], *Signature[Sig, SigFE, PK, PKFE, E, S]] = (*Verifier[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.AggregateVerifier[*PublicKey[Sig, SigFE, PK, PKFE, E, S], Message, *Signature[PK, PKFE, Sig, SigFE, E, S], *Signature[PK, PKFE, Sig, SigFE, E, S]] = (*Verifier[Sig, SigFE, PK, PKFE, E, S])(nil)

		// _ signatures.BatchVerifier[*PublicKey[PK, PKFE, Sig, SigFE, E, S], Message, *Signature[Sig, SigFE, PK, PKFE, E, S]] = (*Verifier[PK, PKFE, Sig, SigFE, E, S])(nil)
		// _ signatures.BatchVerifier[*PublicKey[Sig, SigFE, PK, PKFE, E, S], Message, *Signature[PK, PKFE, Sig, SigFE, E, S]] = (*Verifier[Sig, SigFE, PK, PKFE, E, S])(nil)

		// _ signatures.BatchAggregateVerifier[*PublicKey[PK, PKFE, Sig, SigFE, E, S], Message, *Signature[Sig, SigFE, PK, PKFE, E, S], *Signature[Sig, SigFE, PK, PKFE, E, S]] = (*Verifier[PK, PKFE, Sig, SigFE, E, S])(nil)
		// _ signatures.BatchAggregateVerifier[*PublicKey[Sig, SigFE, PK, PKFE, E, S], Message, *Signature[PK, PKFE, Sig, SigFE, E, S], *Signature[PK, PKFE, Sig, SigFE, E, S]] = (*Verifier[Sig, SigFE, PK, PKFE, E, S])(nil)
	)
}
