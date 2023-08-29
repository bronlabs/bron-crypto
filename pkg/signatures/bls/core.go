package bls

import (
	"encoding/hex"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

// Warning: this is an internal method. We don't check if K and S are different subgroups.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coresign
func coreSign[K KeySubGroup, S SignatureSubGroup](privateKey *PrivateKey[K], message []byte, dst string) (curves.PairingPoint, error) {
	// step 2.6.1
	pointInS := new(S)
	p2 := (*pointInS).HashWithDst(message, dst)
	// step 2.6.2
	result, ok := p2.Mul(privateKey.d).(curves.PairingPoint)
	if !ok {
		return nil, errs.NewInvalidType("result was not pairable. this should never happen")
	}
	if !result.IsTorsionFree() {
		return nil, errs.NewInvalidCurve("point is not on correct subgroup")
	}
	return result, nil
}

// Warning: this is an internal method. We don't check if K and S are different subgroups.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coreverify
func coreVerify[K KeySubGroup, S SignatureSubGroup](publicKey *PublicKey[K], message []byte, value S, dst string) error {
	// step 2.7.2
	if value == nil || message == nil || publicKey == nil {
		return errs.NewInvalidArgument("signature or message or public key cannot be nil or zero")
	}
	// step 2.7.3
	if value.IsIdentity() || !value.IsTorsionFree() {
		return errs.NewMembershipError("signature is not in the correct subgroup")
	}

	// step 2.7.4
	if err := publicKey.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "public key is invalid")
	}
	keysInG1 := publicKey.inG1()
	curve := publicKey.Y.PairingCurve()

	// e(pk, H(m)) == e(g1, s)  OR if signature in G1  e(H(m), pk) == e(s, g2)
	// However, we can reduce the number of miller loops
	// by doing the equivalent of
	// e(pk^-1, H(m)) * e(g1, s) == 1  OR if signature in G1 e(H(m)^-1, pk) * e(s, g2) == 1
	// that'll be done in multipairing

	// step 2.7.6
	// we are calling a method on the same subgroup of "value". value isn't being mutated.
	Q := publicKey.Y.OtherGroup().HashWithDst(message, dst)

	generatorOfKeysSubGroup, ok := publicKey.Y.Generator().(curves.PairingPoint)
	if !ok {
		return errs.NewInvalidType("could not convert public key generator to a pairing point. this should never happen")
	}

	// e(pk^-1, H(m)) * e(g1, s) == 1
	if keysInG1 {
		pkInverse, ok := publicKey.Y.Neg().(curves.PairingPoint)
		if !ok {
			return errs.NewInvalidType("inverse of public key is not pairable. This should never happen.")
		}
		if scalarGt := curve.MultiPairing(pkInverse, Q, generatorOfKeysSubGroup, value); !scalarGt.IsOne() {
			return errs.NewVerificationFailed("incorrect multipairing result")
		}
	}
	// signature in G1 e(H(m)^-1, pk) * e(s, g2) == 1
	hmInverse, ok := Q.Neg().(curves.PairingPoint)
	if !ok {
		return errs.NewInvalidType("inverse of H(m) is not pairable. this should never happen")
	}
	// multipairing expects G1, G2, G1, G2, ....
	if keysInG1 {
		if scalarGt := curve.MultiPairing(publicKey.Y, hmInverse, generatorOfKeysSubGroup, value); scalarGt == nil || !scalarGt.IsOne() {
			return errs.NewVerificationFailed("incorrect multipairing result")
		}
	} else {
		if scalarGt := curve.MultiPairing(hmInverse, publicKey.Y, value, generatorOfKeysSubGroup); scalarGt == nil || !scalarGt.IsOne() {
			return errs.NewVerificationFailed("incorrect multipairing result")
		}
	}
	return nil
}

// Warning: this is an internal method. We don't check if K and S are different subgroups.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coreaggregateverify
func coreAggregateVerify[K KeySubGroup, S SignatureSubGroup](publicKeys []*PublicKey[K], messages [][]byte, aggregatedSignatureValue S, scheme RogueKeyPrevention) error {
	// step 2.9.2
	if aggregatedSignatureValue == nil {
		return errs.NewIsNil("aggregated signature value is nil")
	}
	// step 2.9.3
	if aggregatedSignatureValue.IsIdentity() || !aggregatedSignatureValue.IsTorsionFree() {
		return errs.NewMembershipError("signature is not in the correct subgroup")
	}

	if len(publicKeys) < 1 || publicKeys[0] == nil {
		return errs.NewIncorrectCount("at least one key is required")
	}
	keysInG1 := publicKeys[0].inG1()

	if len(messages) < 1 {
		return errs.NewIncorrectCount("at least one message is required")
	}
	if len(publicKeys) != len(messages) {
		return errs.NewIncorrectCount("the number of public keys does not match the number of messages: %v != %v", len(publicKeys), len(messages))
	}

	dst, err := getDst(scheme, keysInG1)
	if err != nil {
		return errs.WrapFailed(err, "could not get domain separation tag")
	}

	// e(pk_1, H(m_1))*...*e(pk_N, H(m_N)) == e(g1, s) OR if signature in G1 e(H(m_1), pk_1)*...*e(H(m_N), pk_N) == e(s, g2)
	// However, we use only one miller loop
	// by doing the equivalent of
	// e(pk_1, H(m_1))*...*e(pk_N, H(m_N)) * e(g1^-1, s) == 1 OR if signature in G1 e(H(m_1), pk_1)*...*e(H(m_N), pk_N) * e(s^-1, g2) == 1

	multiPairingInputs := make([]curves.PairingPoint, 2*len(publicKeys)+2)
	for mpInputIndexOfG1 := 0; mpInputIndexOfG1 < 2*len(publicKeys); mpInputIndexOfG1 += 2 {
		mpInputIndexOfG2 := mpInputIndexOfG1 + 1
		i := mpInputIndexOfG1 / 2
		publicKey := publicKeys[i]
		message := messages[i]

		// step 2.9.6
		if publicKey == nil {
			return errs.NewIsNil("public key %d is nil", i)
		}
		if err := publicKey.Validate(); err != nil {
			return errs.WrapVerificationFailed(err, "invalid public key %d", i)
		}

		if messages[i] == nil {
			return errs.NewIsNil("nil message is not alloed at index %d", i)
		}
		// step 2.9.8
		Q := publicKey.Y.OtherGroup().HashWithDst(message, dst)

		if keysInG1 {
			multiPairingInputs[mpInputIndexOfG1] = publicKey.Y
			multiPairingInputs[mpInputIndexOfG2] = Q
		} else {
			multiPairingInputs[mpInputIndexOfG1] = Q
			multiPairingInputs[mpInputIndexOfG2] = publicKey.Y
		}
	}

	generatorOfKeysSubGroup, ok := publicKeys[0].Y.Generator().(curves.PairingPoint)
	if !ok {
		return errs.NewInvalidType("could not convert public key generator to a pairing point. this should never happen")
	}

	lastG1Index := 2 * len(publicKeys)
	if keysInG1 {
		gInv, ok := generatorOfKeysSubGroup.Neg().(curves.PairingPoint)
		if !ok {
			return errs.NewInvalidType("this will never be not okay")
		}
		multiPairingInputs[lastG1Index] = gInv
		multiPairingInputs[lastG1Index+1] = aggregatedSignatureValue
	} else {
		sInv, ok := aggregatedSignatureValue.Neg().(curves.PairingPoint)
		if !ok {
			return errs.NewInvalidType("hell is frozen")
		}
		multiPairingInputs[lastG1Index] = sInv
		multiPairingInputs[lastG1Index+1] = generatorOfKeysSubGroup
	}

	if scalarGt := aggregatedSignatureValue.PairingCurve().MultiPairing(multiPairingInputs...); !scalarGt.IsOne() {
		return errs.NewVerificationFailed("incorrect pairing result")
	}
	return nil
}

// PopProve(SK) -> (proof, error): an algorithm that generates a proof of possession for the public key corresponding to secret key SK.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-popprove
func PopProve[K KeySubGroup, S SignatureSubGroup](privateKey *PrivateKey[K]) (*ProofOfPossession[S], error) {
	if SameSubGroup[K, S]() {
		return nil, errs.NewInvalidType("key and signature should be in different subgroups")
	}
	message, err := privateKey.PublicKey.MarshalBinary()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not marshal public key to binary")
	}
	dst := blsPopProofDstInG1
	if !privateKey.PublicKey.inG1() {
		dst = blsPopProofDstInG2
	}
	point, err := coreSign[K, S](privateKey, message, dst)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce pop")
	}
	return &ProofOfPossession[S]{
		Value: point,
	}, nil
}

// PopVerify verifies proof of possession of public key
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-popverify
func PopVerify[K KeySubGroup, S SignatureSubGroup](publicKey *PublicKey[K], pop *ProofOfPossession[S]) error {
	if SameSubGroup[K, S]() {
		return errs.NewInvalidType("key and signature should be in different subgroups")
	}
	message, err := publicKey.MarshalBinary()
	if err != nil {
		return errs.WrapFailed(err, "could not marshal public ky")
	}
	dst := blsPopProofDstInG1
	if !publicKey.inG1() {
		dst = blsPopProofDstInG2
	}
	p, ok := pop.Value.(S)
	if !ok {
		return errs.NewInvalidType("pop is not in the right subgroup")
	}
	return coreVerify(publicKey, message, p, dst)
}

// See section 3.2.1 from
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-sign
func augmentMessage[K KeySubGroup](message []byte, publicKey *PublicKey[K]) ([]byte, error) {
	result, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not marshal public key to binary")
	}
	result = append(result, message...)
	return result, nil
}

// AggregateSignatures aggregates multiple signatures into one.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-aggregate
func AggregateSignatures[S SignatureSubGroup](signatures ...*Signature[S]) (*Signature[S], error) {
	if len(signatures) < 1 {
		return nil, errs.NewIncorrectCount("at least one signature is needed")
	}
	s := new(S)
	result := (*s).Identity()
	for i, signature := range signatures {
		if signature == nil {
			return nil, errs.NewIsNil("signature %d is nil", i)
		}
		if signature.Value.IsIdentity() || !signature.Value.IsTorsionFree() || signature.Value.ClearCofactor().IsIdentity() {
			return nil, errs.NewVerificationFailed("signature is invalid")
		}
		result = result.Add(signature.Value)
	}
	value, ok := result.(curves.PairingPoint)
	if !ok {
		return nil, errs.NewInvalidType("couldn't convert to pairing point")
	}
	return &Signature[S]{
		Value: value,
	}, nil
}

func AggregatePublicKeys[K KeySubGroup](publicKeys ...*PublicKey[K]) (*PublicKey[K], error) {
	if len(publicKeys) < 1 {
		return nil, errs.NewIncorrectCount("at least one public key is needed")
	}
	k := new(K)
	result := (*k).Identity()
	for i, publicKey := range publicKeys {
		if publicKey == nil {
			return nil, errs.NewIsNil("public key %d is nil", i)
		}
		if publicKey.Y.IsIdentity() || !publicKey.Y.IsTorsionFree() || publicKey.Y.ClearCofactor().IsIdentity() {
			return nil, errs.NewVerificationFailed("public key is invalid")
		}
		result = result.Add(publicKey.Y)
	}
	value, ok := result.(curves.PairingPoint)
	if !ok {
		return nil, errs.NewInvalidType("couldn't convert to pairing point")
	}
	return &PublicKey[K]{
		Y: value,
	}, nil
}

func SameSubGroup[K KeySubGroup, S SignatureSubGroup]() bool {
	p := new(K)
	q := new(S)
	return (*p).CurveName() == (*q).CurveName()
}

func allUnique(messages [][]byte) (bool, error) {
	if messages == nil {
		return false, errs.NewIsNil("messages is nil")
	}
	seen := map[string]bool{}
	for i, message := range messages {
		if message == nil {
			return false, errs.NewIsNil("message %d is nil", i)
		}
		m := hex.EncodeToString(message)
		if _, exists := seen[m]; exists {
			return false, nil
		}
		seen[m] = true
	}
	return true, nil
}

func getDst(scheme RogueKeyPrevention, keysInG1 bool) (string, error) {
	switch scheme {
	case Basic:
		if keysInG1 {
			return blsSignatureBasicDstInG2, nil
		}
		return blsSignatureBasicDstInG1, nil
	case MessageAugmentation:
		if keysInG1 {
			return blsSignatureAugDstInG2, nil
		}
		return blsSignatureAugDstInG1, nil
	case POP:
		if keysInG1 {
			return blsSignaturePopDstInG2, nil
		}
		return blsSignaturePopDstInG1, nil
	default:
		return "", errs.NewInvalidType("scheme type %v not implemented", scheme)
	}
}
