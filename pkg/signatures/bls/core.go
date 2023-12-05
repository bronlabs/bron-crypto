package bls

import (
	"bytes"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// Warning: this is an internal method. We don't check if K and S are different subgroups.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coresign
func coreSign[K KeySubGroup, S SignatureSubGroup](privateKey *PrivateKey[K], message, dst []byte) (curves.PairingPoint, error) {
	// step 2.6.1
	Hm, err := privateKey.d.OtherGroup().HashWithDst(message, dst)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not hash message")
	}
	// step 2.6.2
	result, ok := Hm.Mul(privateKey.d).(curves.PairingPoint)
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
func coreVerify[K KeySubGroup, S SignatureSubGroup](publicKey *PublicKey[K], message []byte, value S, dst []byte) error {
	// step 2.7.2
	if value == nil || message == nil || publicKey == nil {
		return errs.NewInvalidArgument("signature or message or public key cannot be nil or zero")
	}
	// step 2.7.3
	if value.IsIdentity() || !value.IsTorsionFree() {
		return errs.NewMembership("signature is not in the correct subgroup")
	}

	// step 2.7.4
	if err := publicKey.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "public key is invalid")
	}
	keysInG1 := publicKey.InG1()
	curve := publicKey.Y.PairingCurve()

	// e(pk, H(m)) == e(g1, s)  OR if signature in G1  e(H(m), pk) == e(s, g2)
	// However, we can reduce the number of miller loops
	// by doing the equivalent of
	// e(pk^-1, H(m)) * e(g1, s) == 1  OR if signature in G1 e(H(m), pk^-1) * e(s, g2) == 1
	// that'll be done in multipairing

	// step 2.7.6
	Hm, err := publicKey.Y.OtherGroup().HashWithDst(message, dst)
	if err != nil {
		return errs.WrapHashingFailed(err, "could not hash message")
	}

	generatorOfKeysSubGroup, ok := publicKey.Y.Generator().(curves.PairingPoint)
	if !ok {
		return errs.NewInvalidType("could not convert public key generator to a pairing point. this should never happen")
	}
	pkInverse, ok := publicKey.Y.Neg().(curves.PairingPoint)
	if !ok {
		return errs.NewInvalidType("inverse of public key is not pairable. This should never happen.")
	}

	// e(pk^-1, H(m)) * e(g1, s) == 1
	if keysInG1 {
		if scalarGt := curve.MultiPairing(pkInverse, Hm, generatorOfKeysSubGroup, value); !scalarGt.IsOne() {
			return errs.NewVerificationFailed("incorrect multipairing result")
		}
	} else {
		// e(H(m), pk^-1) * e(s, g2) == 1
		if scalarGt := curve.MultiPairing(Hm, pkInverse, value, generatorOfKeysSubGroup); !scalarGt.IsOne() {
			return errs.NewVerificationFailed("incorrect multipairing result")
		}
	}
	return nil
}

// Warning: this is an internal method. We don't check if K and S are different subgroups.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coreaggregateverify
func coreAggregateVerify[K KeySubGroup, S SignatureSubGroup](publicKeys []*PublicKey[K], messages [][]byte, aggregatedSignatureValue S, dst []byte) error {
	// step 2.9.2
	if aggregatedSignatureValue == nil {
		return errs.NewIsNil("aggregated signature value is nil")
	}
	// step 2.9.3
	if aggregatedSignatureValue.IsIdentity() || !aggregatedSignatureValue.IsTorsionFree() {
		return errs.NewMembership("signature is not in the correct subgroup")
	}

	if len(publicKeys) < 1 || publicKeys[0] == nil {
		return errs.NewIncorrectCount("at least one key is required")
	}
	keysInG1 := publicKeys[0].InG1()

	if len(messages) < 1 {
		return errs.NewIncorrectCount("at least one message is required")
	}
	if len(publicKeys) != len(messages) {
		return errs.NewIncorrectCount("the number of public keys does not match the number of messages: %v != %v", len(publicKeys), len(messages))
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
		Q, err := publicKey.Y.OtherGroup().HashWithDst(message, dst)
		if err != nil {
			return errs.WrapHashingFailed(err, "could not hash message %d", i)
		}

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
	dst := GetPOPDst(privateKey.PublicKey.InG1())
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
	dst := GetPOPDst(publicKey.InG1())
	p, ok := pop.Value.(S)
	if !ok {
		return errs.NewInvalidType("pop is not in the right subgroup")
	}
	return coreVerify(publicKey, message, p, dst)
}

// See section 3.2.1 from
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-sign
func AugmentMessage[K KeySubGroup](message []byte, publicKey *PublicKey[K]) ([]byte, error) {
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
	for i, message := range messages {
		if message == nil {
			return false, errs.NewIsNil("message %d is nil", i)
		}
		for j := i + 1; j < len(messages); j++ {
			if messages[j] == nil {
				return false, errs.NewIsNil("message %d is nil", j)
			}
			if bytes.Equal(message, messages[j]) {
				return false, errs.NewDuplicate("message %d and %d are the same", i, j)
			}
		}
	}
	return true, nil
}

func GetDst(scheme RogueKeyPrevention, keysInG1 bool) ([]byte, error) {
	switch scheme {
	case Basic:
		if keysInG1 {
			return []byte(DstSignatureBasicInG2), nil
		}
		return []byte(DstSignatureBasicInG1), nil
	case MessageAugmentation:
		if keysInG1 {
			return []byte(DstSignatureAugInG2), nil
		}
		return []byte(DstSignatureAugInG1), nil
	case POP:
		if keysInG1 {
			return []byte(DstSignaturePopInG2), nil
		}
		return []byte(DstSignaturePopInG1), nil
	default:
		return []byte(""), errs.NewInvalidType("scheme type %v not implemented", scheme)
	}
}

func GetPOPDst(keysInG1 bool) []byte {
	if !keysInG1 {
		return []byte(DstPopProofInG2)
	}
	return []byte(DstPopProofInG1)
}
