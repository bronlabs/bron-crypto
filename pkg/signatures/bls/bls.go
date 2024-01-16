package bls

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

const (
	// Domain separation tag for basic signatures
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.1
	DstSignatureBasicInG2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
	// Domain separation tag for basic signatures
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.2
	DstSignatureAugInG2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_"
	// Domain separation tag for proof of possession signatures
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
	DstSignaturePopInG2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
	// Domain separation tag for proof of possession proofs
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
	DstPopProofInG2 = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

	// Domain separation tag for basic signatures
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.1
	DstSignatureBasicInG1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
	// Domain separation tag for basic signatures
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.2
	DstSignatureAugInG1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_"
	// Domain separation tag for proof of possession signatures
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
	DstSignaturePopInG1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"
	// Domain separation tag for proof of possession proofs
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
	DstPopProofInG1 = "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"
)

type RogueKeyPrevention int

const (
	Basic RogueKeyPrevention = iota
	MessageAugmentation
	POP
)

type Signer[K KeySubGroup, S SignatureSubGroup] struct {
	Scheme     RogueKeyPrevention
	PrivateKey *PrivateKey[K]

	_ types.Incomparable
}

func NewSigner[K KeySubGroup, S SignatureSubGroup](privateKey *PrivateKey[K], scheme RogueKeyPrevention) (*Signer[K, S], error) {
	if SameSubGroup[K, S]() {
		return nil, errs.NewInvalidType("key and signature subgroups should not be the same")
	}
	if err := privateKey.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "private key validation failed")
	}
	signer := &Signer[K, S]{
		Scheme:     scheme,
		PrivateKey: privateKey,
	}
	err := signer.Validate()
	if err != nil {
		return nil, errs.WrapFailed(err, "signer validation failed")
	}
	return signer, nil
}

// Sign implements the signing algorithm for all 3 schemes
// Basic: identical to core sign.
// MessageAugmentation: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-sign
// POP: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
func (s *Signer[K, S]) Sign(message, tag []byte) (*Signature[S], *ProofOfPossession[S], error) {
	var err error
	if len(message) == 0 {
		return nil, nil, errs.NewIsNil("message cannot be nil")
	}
	if err := s.PrivateKey.Validate(); err != nil {
		return nil, nil, errs.WrapFailed(err, "could not validate private key")
	}

	var pop *ProofOfPossession[S]
	pop = nil

	switch s.Scheme {
	// identical to coreSign: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-3.1-2
	case Basic:
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-sign
	case MessageAugmentation:
		// step 3.2.1.2 (namely, the pk || message portion)
		message, err = AugmentMessage(message, s.PrivateKey.PublicKey)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not augment message")
		}
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
	case POP:
		pop, err = PopProve[K, S](s.PrivateKey)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not produce proof of possession")
		}
	default:
		return nil, nil, errs.NewInvalidType("rogue key prevention scheme %d is not supported", s.Scheme)
	}
	var dst []byte
	if len(tag) == 0 {
		dst, err = GetDst(s.Scheme, s.PrivateKey.PublicKey.InG1())
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not get domain separation tag")
		}
	} else {
		dst = tag
	}

	point, err := coreSign[K, S](s.PrivateKey, message, dst)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not sign")
	}

	signature := &Signature[S]{
		Value: point,
	}

	return signature, pop, nil
}

func (s *Signer[K, S]) Validate() error {
	if s == nil {
		return errs.NewIsNil("signer is nil")
	}
	if s.PrivateKey == nil {
		return errs.NewIsNil("signer's key is nil")
	}
	if SameSubGroup[K, S]() {
		return errs.NewInvalidType("key and signature should be in different subgroups")
	}
	return nil
}

// Verify implements the verification algorithm for all 3 schemes
// Basic: identical to core sign.
// Verify: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-verify
// POP: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
func Verify[K KeySubGroup, S SignatureSubGroup](publicKey *PublicKey[K], signature *Signature[S], message []byte, pop *ProofOfPossession[S], scheme RogueKeyPrevention, tag []byte) error {
	if SameSubGroup[K, S]() {
		return errs.NewInvalidType("key and signature should be in different subgroups")
	}

	var err error
	switch scheme {
	// identical to core verify.
	case Basic:
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-verify
	case MessageAugmentation:
		if len(message) == 0 {
			return errs.NewIsNil("message cannot be nil")
		}
		if publicKey == nil {
			return errs.NewIsNil("public key is nil")
		}
		// step 3.2.2.1 (PK || message)
		message, err = AugmentMessage(message, publicKey)
		if err != nil {
			return errs.WrapFailed(err, "could not augment message")
		}
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-3.3
	case POP:
		if pop == nil {
			return errs.NewIsNil("pop is nil")
		}
		if publicKey == nil {
			return errs.NewIsNil("public key is nil")
		}
		// pk must be acompanied with pop
		if err := PopVerify(publicKey, pop); err != nil {
			return errs.WrapVerificationFailed(err, "invalid rogue key prevention")
		}
	default:
		return errs.NewInvalidType("rogue key prevention scheme %d is not supported", scheme)
	}

	var dst []byte
	if len(tag) == 0 {
		dst, err = GetDst(scheme, publicKey.InG1())
		if err != nil {
			return errs.WrapFailed(err, "could not get domain separation tag")
		}
	} else {
		dst = tag
	}

	if err := coreVerify[K, S](publicKey, message, signature.Value, dst); err != nil {
		return errs.WrapVerificationFailed(err, "invalid signature")
	}
	return nil
}

// AggregateVerify implements aggregate verify functions for the 3 signature schemes.
// Basic: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-aggregateverify
// MessageAugmentation: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-aggregateverify-2
// POP: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
func AggregateVerify[K KeySubGroup, S SignatureSubGroup](publicKeys []*PublicKey[K], messages [][]byte, aggregatedSignature *Signature[S], pops []*ProofOfPossession[S], scheme RogueKeyPrevention, tag []byte) error {
	if SameSubGroup[K, S]() {
		return errs.NewInvalidType("key and signature should be in different subgroups")
	}

	if len(publicKeys) != len(messages) {
		return errs.NewIncorrectCount("#public keys != #messages")
	}

	switch scheme {
	// case 3.1.1
	case Basic:
		if len(pops) > 0 {
			return errs.NewIncorrectCount("nonzero number of pops when scheme is basic")
		}
		// step 3.1.1.1
		areAllUnique, err := allUnique(messages)
		if err != nil {
			return errs.WrapFailed(err, "could not determine if all messages are unique")
		}
		if !areAllUnique {
			return errs.NewVerificationFailed("not all messages are unique")
		}
	// case 3.3
	case POP:
		if len(publicKeys) != len(pops) {
			return errs.NewIncorrectCount("#publicKeys != #pops")
		}
		for i, publicKey := range publicKeys {
			if err := PopVerify(publicKey, pops[i]); err != nil {
				return errs.WrapVerificationFailed(err, "pop %d is invalid", i)
			}
		}
	// case 3.2.3 https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-aggregateverify-2
	case MessageAugmentation:
		if len(pops) > 0 {
			return errs.NewIncorrectCount("nonzero number of pops when scheme is message augmentation")
		}
		// step 3.2.3.1
		for i, publicKey := range publicKeys {
			// step 3.2.3.2
			augmentedMessage, err := AugmentMessage(messages[i], publicKey)
			if err != nil {
				return errs.WrapFailed(err, " could not augment message")
			}
			messages[i] = augmentedMessage
		}
	default:
		return errs.NewInvalidType("rogue key prevention scheme %d is not supported", scheme)
	}

	var dst []byte
	var err error
	if len(tag) == 0 {
		dst, err = GetDst(scheme, bls12381.GetSourceSubGroup[K]().Name() == bls12381.NameG1)
		if err != nil {
			return errs.WrapFailed(err, "could not get domain separation tag")
		}
	} else {
		dst = tag
	}

	// step 3.1.1.2
	if err := coreAggregateVerify[K, S](publicKeys, messages, aggregatedSignature.Value, dst); err != nil {
		return errs.WrapVerificationFailed(err, "invalid signature bundle")
	}
	return nil
}

//	FastAggregateVerify is a verification algorithm for the aggregate of multiple signatures on the same message. This function is faster than AggregateVerify.
//
// All public keys passed as arguments to this algorithm MUST have a corresponding proof of possession, and the result of evaluating PopVerify on each public key and its proof MUST be VALID. The caller is responsible for ensuring that this precondition is met. If it is violated, this scheme provides no security against aggregate signature forgery.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-fastaggregateverify
func FastAggregateVerify[K KeySubGroup, S SignatureSubGroup](publicKeys []*PublicKey[K], message []byte, aggregatedSignature *Signature[S], pops []*ProofOfPossession[S]) error {
	if SameSubGroup[K, S]() {
		return errs.NewInvalidType("key and signature should be in different subgroups")
	}

	if aggregatedSignature == nil || message == nil {
		return errs.NewIsNil("message or aggregatd signature can't be nil")
	}

	if len(publicKeys) != len(pops) {
		return errs.NewIncorrectCount("#public keys != #pops")
	}
	if len(publicKeys) < 2 {
		return errs.NewIncorrectCount("at least two public key is needed")
	}

	// step 3.3.4.1-5
	aggregatePublicKey, err := AggregatePublicKeys(publicKeys...)
	if err != nil {
		return errs.WrapFailed(err, "could not aggregate public keys")
	}
	// we verify pop within the same function for ease of use
	for i, pop := range pops {
		if pop == nil {
			return errs.NewIsNil("pop %d is nil", i)
		}
		if err := PopVerify(publicKeys[i], pop); err != nil {
			return errs.WrapVerificationFailed(err, "invalid pop")
		}
	}

	dst, err := GetDst(POP, publicKeys[0].InG1())
	if err != nil {
		return errs.WrapFailed(err, "could not get domain separation tag")
	}

	// step 3.3.4.6
	if err := coreVerify[K, S](aggregatePublicKey, message, aggregatedSignature.Value, dst); err != nil {
		return errs.WrapVerificationFailed(err, "invalid signature")
	}
	return nil
}
