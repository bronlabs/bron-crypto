package bls

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
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

	_ ds.Incomparable
}

func NewSigner[K KeySubGroup, S SignatureSubGroup](privateKey *PrivateKey[K], scheme RogueKeyPrevention) (*Signer[K, S], error) {
	if SameSubGroup[K, S]() {
		return nil, errs.NewType("key and signature subgroups should not be the same")
	}
	if err := privateKey.Validate(); err != nil {
		return nil, errs.WrapArgument(err, "private key validation failed")
	}
	signer := &Signer[K, S]{
		Scheme:     scheme,
		PrivateKey: privateKey,
	}
	if err := signer.Validate(); err != nil {
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
		return nil, nil, errs.NewType("rogue key prevention scheme %d is not supported", s.Scheme)
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
		return errs.NewType("key and signature should be in different subgroups")
	}
	return nil
}

// Verify implements the verification algorithm for all 3 schemes
// Basic: identical to core sign.
// Verify: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-verify
// POP: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
func Verify[K KeySubGroup, S SignatureSubGroup](publicKey *PublicKey[K], signature *Signature[S], message []byte, pop *ProofOfPossession[S], scheme RogueKeyPrevention, tag []byte) error {
	if SameSubGroup[K, S]() {
		return errs.NewType("key and signature should be in different subgroups")
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
			return errs.WrapVerification(err, "invalid rogue key prevention")
		}
	default:
		return errs.NewType("rogue key prevention scheme %d is not supported", scheme)
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
		return errs.WrapVerification(err, "invalid signature")
	}
	return nil
}

// AggregateVerify implements aggregate verify functions for the 3 signature schemes.
// Basic: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-aggregateverify
// MessageAugmentation: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-aggregateverify-2
// POP: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
func AggregateVerify[K KeySubGroup, S SignatureSubGroup](publicKeys []*PublicKey[K], messages [][]byte, aggregatedSignature *Signature[S], pops []*ProofOfPossession[S], scheme RogueKeyPrevention, tag []byte) error {
	if SameSubGroup[K, S]() {
		return errs.NewType("key and signature should be in different subgroups")
	}

	if len(publicKeys) != len(messages) {
		return errs.NewSize("#public keys != #messages")
	}

	switch scheme {
	// case 3.1.1
	case Basic:
		if len(pops) > 0 {
			return errs.NewSize("nonzero number of pops when scheme is basic")
		}
		// step 3.1.1.1
		if err := allUnique(messages); err != nil {
			return errs.WrapFailed(err, "message uniqueness")
		}
	// case 3.3
	case POP:
		if len(publicKeys) != len(pops) {
			return errs.NewSize("#publicKeys != #pops")
		}
		for i, publicKey := range publicKeys {
			if err := PopVerify(publicKey, pops[i]); err != nil {
				return errs.WrapVerification(err, "pop %d is invalid", i)
			}
		}
	// case 3.2.3 https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-aggregateverify-2
	case MessageAugmentation:
		if len(pops) > 0 {
			return errs.NewSize("nonzero number of pops when scheme is message augmentation")
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
		return errs.NewType("rogue key prevention scheme %d is not supported", scheme)
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
		return errs.WrapVerification(err, "invalid signature bundle")
	}
	return nil
}

//	FastAggregateVerify is a verification algorithm for the aggregate of multiple signatures on the same message. This function is faster than AggregateVerify.
//
// All public keys passed as arguments to this algorithm MUST have a corresponding proof of possession, and the result of evaluating PopVerify on each public key and its proof MUST be VALID. The caller is responsible for ensuring that this precondition is met. If it is violated, this scheme provides no security against aggregate signature forgery.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-fastaggregateverify
func FastAggregateVerify[K KeySubGroup, S SignatureSubGroup](publicKeys []*PublicKey[K], message []byte, aggregatedSignature *Signature[S], pops []*ProofOfPossession[S]) error {
	if SameSubGroup[K, S]() {
		return errs.NewType("key and signature should be in different subgroups")
	}

	if aggregatedSignature == nil || message == nil {
		return errs.NewIsNil("message or aggregatd signature can't be nil")
	}

	if len(publicKeys) != len(pops) {
		return errs.NewSize("#public keys != #pops")
	}
	if len(publicKeys) < 2 {
		return errs.NewSize("at least two public key is needed")
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
			return errs.WrapVerification(err, "invalid pop")
		}
	}

	dst, err := GetDst(POP, publicKeys[0].InG1())
	if err != nil {
		return errs.WrapFailed(err, "could not get domain separation tag")
	}

	// step 3.3.4.6
	if err := coreVerify[K, S](aggregatePublicKey, message, aggregatedSignature.Value, dst); err != nil {
		return errs.WrapVerification(err, "invalid signature")
	}
	return nil
}

// BatchAggregateVerify simultaneously verifies n aggregated signatures where each signature is aggregation of M signatures from the provided public keys. Each aggregated signature may have different rogue key prevention schemes.
// https://ethresear.ch/t/security-of-bls-batch-verification/10748
func BatchAggregateVerify[K KeySubGroup, S SignatureSubGroup](publicKeys []*PublicKey[K], batchMessages [][][]byte, aggregatedSignatures []*Signature[S], pops []*ProofOfPossession[S], schemes []RogueKeyPrevention, tags [][]byte, prng io.Reader) error {
	if err := validateInputsBatchAggregateVerify(publicKeys, batchMessages, aggregatedSignatures, schemes, tags, prng); err != nil {
		return errs.WrapArgument(err, "invalid arguments")
	}
	batchSize := len(aggregatedSignatures)
	keysInG1 := publicKeys[0].InG1()
	keySubGroup := bls12381.GetSourceSubGroup[K]()
	signatureSubGroup := bls12381.GetSourceSubGroup[S]()
	verifiedPops := false
	sStar := signatureSubGroup.AdditiveIdentity()
	multiPairingInputs := []curves.PairingPoint{}

	for batch := 0; batch < batchSize; batch++ {
		scheme := schemes[batch]
		messages := batchMessages[batch]
		aggregatedSignature := aggregatedSignatures[batch]

		if len(messages) != len(publicKeys) {
			return errs.NewSize("#messages != #public keys in batch %d", batch)
		}

		var dst []byte
		var err error
		if tags == nil || len(tags) < batchSize || len(tags[batch]) == 0 {
			dst, err = GetDst(scheme, keysInG1)
			if err != nil {
				return errs.WrapFailed(err, "could not get domain separation tag")
			}
		} else {
			dst = tags[batch]
		}

		switch scheme {
		case Basic:
			if err := allUnique(messages); err != nil {
				return errs.WrapFailed(err, "message uniqueness")
			}
		case POP:
			if !verifiedPops {
				if len(publicKeys) != len(pops) {
					return errs.NewSize("#publicKeys != #pops")
				}
				for i, publicKey := range publicKeys {
					if err := PopVerify(publicKey, pops[i]); err != nil {
						return errs.WrapVerification(err, "pop %d is invalid", i)
					}
				}
				verifiedPops = true
			}
		case MessageAugmentation:
			for i, publicKey := range publicKeys {
				augmentedMessage, err := AugmentMessage(messages[i], publicKey)
				if err != nil {
					return errs.WrapFailed(err, " could not augment message")
				}
				messages[i] = augmentedMessage
			}
		default:
			return errs.NewType("rogue key prevention scheme %d is not supported", scheme)
		}

		r, err := signatureSubGroup.ScalarField().Random(prng)
		if err != nil {
			return errs.WrapRandomSample(err, "could not compute r")
		}

		sStar = sStar.Add(aggregatedSignature.Value.ScalarMul(r))

		for i, m := range messages {
			M, err := signatureSubGroup.HashWithDst(string(dst), m)
			if err != nil {
				return errs.WrapHashing(err, "could not compute hash of m_%d", i)
			}
			rM := M.ScalarMul(r).(curves.PairingPoint)

			if keysInG1 {
				multiPairingInputs = append(multiPairingInputs, publicKeys[i].Y, rM)
			} else {
				multiPairingInputs = append(multiPairingInputs, rM, publicKeys[i].Y)
			}
		}
	}

	if keysInG1 {
		gInv := keySubGroup.Generator().Neg().(curves.PairingPoint)
		multiPairingInputs = append(multiPairingInputs, gInv, sStar.(curves.PairingPoint))
	} else {
		sStarInv := sStar.Neg().(curves.PairingPoint)
		multiPairingInputs = append(multiPairingInputs, sStarInv, keySubGroup.Generator().(curves.PairingPoint))
	}

	scalarGt, err := aggregatedSignatures[0].Value.PairingCurve().MultiPair(multiPairingInputs...)
	if err != nil {
		return errs.WrapFailed(err, "multipairing failed")
	}
	if !scalarGt.IsMultiplicativeIdentity() {
		return errs.NewVerification("batch")
	}
	return nil
}

func validateInputsBatchAggregateVerify[K KeySubGroup, S SignatureSubGroup](publicKeys []*PublicKey[K], batchMessages [][][]byte, aggregatedSignatures []*Signature[S], schemes []RogueKeyPrevention, tags [][]byte, prng io.Reader) error {
	if SameSubGroup[K, S]() {
		return errs.NewType("key and signature should be in different subgroups")
	}
	batchSize := len(aggregatedSignatures)
	if batchSize == 0 {
		return errs.NewSize("#aggregated signatures == 0")
	}
	if batchSize != len(batchMessages) {
		return errs.NewSize("#batch messages != batch size")
	}
	if batchSize != len(schemes) {
		return errs.NewSize("#schemes != batch size")
	}
	if tags != nil && batchSize != len(tags) {
		return errs.NewSize("#tags != batch size")
	}
	if len(publicKeys) == 0 {
		return errs.NewSize("#PublicKeys == 0")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	for batch := 0; batch < batchSize; batch++ {
		if aggregatedSignatures[batch] == nil {
			return errs.NewIsNil("aggregated signature of batch %d", batch)
		}
		if err := subgroupCheck[S](aggregatedSignatures[batch].Value); err != nil {
			return errs.WrapValidation(err, "aggregated signature of batch %d", batch)
		}
	}
	for i, pk := range publicKeys {
		if pk == nil {
			return errs.NewIsNil("public key %d", i)
		}
		if err := subgroupCheck[K](pk.Y); err != nil {
			return errs.WrapValidation(err, "public key %d", i)
		}
	}
	allPublicKeys := make([]curves.Point, len(publicKeys))
	for i, pk := range publicKeys {
		allPublicKeys[i] = pk.Y
	}
	if len(allPublicKeys) > 1 && !curveutils.AllPointsOfSameCurve(publicKeys[0].Y.Curve(), allPublicKeys...) {
		return errs.NewType("public keys are not of the same curve")
	}
	return nil
}

// BatchVerify simultaneously verifies n signatures of the provided messages with the provided public keys. Each signature may have its own rogue key prevention scheme.
// https://github.com/ethereum/bls12-381-tests/blob/master/main.py#L453
// https://ethresear.ch/t/security-of-bls-batch-verification/10748
func BatchVerify[K KeySubGroup, S SignatureSubGroup](publicKeys []*PublicKey[K], messages [][]byte, signatures []*Signature[S], pops []*ProofOfPossession[S], schemes []RogueKeyPrevention, tags [][]byte, prng io.Reader) error {
	if err := validateInputsBatchVerify(publicKeys, messages, signatures, schemes, tags, prng); err != nil {
		return errs.WrapArgument(err, "invalid arguments")
	}
	batchSize := len(signatures)
	keysInG1 := publicKeys[0].InG1()
	keySubGroup := bls12381.GetSourceSubGroup[K]()
	signatureSubGroup := bls12381.GetSourceSubGroup[S]()
	sStar := signatureSubGroup.AdditiveIdentity()
	multiPairingInputs := []curves.PairingPoint{}

	for batch := 0; batch < batchSize; batch++ {
		signature := signatures[batch]
		message := messages[batch]
		publicKey := publicKeys[batch]
		scheme := schemes[batch]

		var dst []byte
		var err error
		if tags == nil || len(tags) < batchSize || len(tags[batch]) == 0 {
			dst, err = GetDst(scheme, keysInG1)
			if err != nil {
				return errs.WrapFailed(err, "could not get domain separation tag")
			}
		} else {
			dst = tags[batch]
		}

		switch scheme {
		case Basic:
		case POP:
			if len(publicKeys) != len(pops) {
				return errs.NewSize("#publicKeys != #pops")
			}
			if err := PopVerify(publicKey, pops[batch]); err != nil {
				return errs.WrapVerification(err, "pop %d is invalid", batch)
			}
		case MessageAugmentation:
			message, err = AugmentMessage(message, publicKey)
			if err != nil {
				return errs.WrapFailed(err, " could not augment message")
			}
		default:
			return errs.NewType("rogue key prevention scheme %d is not supported", scheme)
		}

		r, err := signatureSubGroup.ScalarField().Random(prng)
		if err != nil {
			return errs.WrapRandomSample(err, "could not compute r")
		}

		sStar = sStar.Add(signature.Value.ScalarMul(r))

		M, err := signatureSubGroup.HashWithDst(string(dst), message)
		if err != nil {
			return errs.WrapHashing(err, "could not compute hash of m_%d", batch)
		}
		rM := M.ScalarMul(r).(curves.PairingPoint)

		if keysInG1 {
			multiPairingInputs = append(multiPairingInputs, publicKey.Y, rM)
		} else {
			multiPairingInputs = append(multiPairingInputs, rM, publicKey.Y)
		}
	}

	if keysInG1 {
		gInv := keySubGroup.Generator().Neg().(curves.PairingPoint)
		multiPairingInputs = append(multiPairingInputs, gInv, sStar.(curves.PairingPoint))
	} else {
		sStarInv := sStar.Neg().(curves.PairingPoint)
		multiPairingInputs = append(multiPairingInputs, sStarInv, keySubGroup.Generator().(curves.PairingPoint))
	}

	scalarGt, err := signatures[0].Value.PairingCurve().MultiPair(multiPairingInputs...)
	if err != nil {
		return errs.WrapFailed(err, "multipairing failed")
	}
	if !scalarGt.IsMultiplicativeIdentity() {
		return errs.NewVerification("batch")
	}
	return nil
}

func validateInputsBatchVerify[K KeySubGroup, S SignatureSubGroup](publicKeys []*PublicKey[K], messages [][]byte, signatures []*Signature[S], schemes []RogueKeyPrevention, tags [][]byte, prng io.Reader) error {
	if SameSubGroup[K, S]() {
		return errs.NewType("key and signature should be in different subgroups")
	}
	batchSize := len(signatures)
	if batchSize == 0 {
		return errs.NewSize("#signatures == 0")
	}
	if batchSize != len(messages) {
		return errs.NewSize("#messages != batch size")
	}
	if batchSize != len(schemes) {
		return errs.NewSize("#schemes != batch size")
	}
	if tags != nil && batchSize != len(tags) {
		return errs.NewSize("#tags != batch size")
	}
	if batchSize != len(publicKeys) {
		return errs.NewSize("#PublicKeys != batch size")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	for batch := 0; batch < batchSize; batch++ {
		if signatures[batch] == nil {
			return errs.NewIsNil("signature of batch %d", batch)
		}
		if err := subgroupCheck[S](signatures[batch].Value); err != nil {
			return errs.WrapValidation(err, "signature of batch %d", batch)
		}
		if publicKeys[batch] == nil {
			return errs.NewIsNil("public key %d", batch)
		}
		if err := subgroupCheck[K](publicKeys[batch].Y); err != nil {
			return errs.WrapValidation(err, "public key %d", batch)
		}
	}
	return nil
}
