package bls

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
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

type ShortPublicKeySigner[C1 curves.Curve[P1, B1, S], P1 curves.Point[P1, B1, S], B1 fields.FiniteFieldElement[B1], C2 curves.Curve[P2, B2, S], P2 curves.Point[P2, B2, S], B2 fields.FiniteFieldElement[B2], G groups.FiniteAbelianMultiplicativeGroup[GE, S], GE groups.FiniteAbelianMultiplicativeGroupElement[GE, S], S fields.PrimeFieldElement[S]] struct {
	scheme  RogueKeyPrevention
	sk      *PrivateKey[P1, B1, S]
	pairing curves.Pairing[C1, P1, B1, C2, P2, B2, G, GE, S]
}

func NewShortPublicKeySigner[C1 curves.Curve[P1, B1, S], P1 curves.Point[P1, B1, S], B1 fields.FiniteFieldElement[B1], C2 curves.Curve[P2, B2, S], P2 curves.Point[P2, B2, S], B2 fields.FiniteFieldElement[B2], S fields.PrimeFieldElement[S], G groups.FiniteAbelianMultiplicativeGroup[GE, S], GE groups.FiniteAbelianMultiplicativeGroupElement[GE, S]](scheme RogueKeyPrevention, sk *PrivateKey[P1, B1, S], pairing curves.Pairing[C1, P1, B1, C2, P2, B2, G, GE, S]) *ShortPublicKeySigner[C1, P1, B1, C2, P2, B2, G, GE, S] {
	return &ShortPublicKeySigner[C1, P1, B1, C2, P2, B2, G, GE, S]{
		scheme:  scheme,
		sk:      sk,
		pairing: pairing,
	}
}

func (s *ShortPublicKeySigner[C1, P1, B1, C2, P2, B2, G, GE, S]) Sign(message, tag []byte) (*Signature[P2, B2, S], *ProofOfPossession[P1, B1, S], error) {
	var err error
	if len(message) == 0 {
		return nil, nil, errs.NewIsNil("message cannot be nil")
	}
	//if err := s.PrivateKey.Validate(); err != nil {
	//	return nil, nil, errs.WrapFailed(err, "could not validate private key")
	//}

	var pop *ProofOfPossession[P1, B1, S]
	pop = nil

	switch s.scheme {
	// identical to coreSign: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-3.1-2
	case Basic:
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-sign
	//case MessageAugmentation:
	//	//panic("not implemented")
	//	//// step 3.2.1.2 (namely, the pk || message portion)
	//	//message, err = AugmentMessage(message, s.PrivateKey.PublicKey)
	//	//if err != nil {
	//	//	return nil, nil, errs.WrapFailed(err, "could not augment message")
	//	//}
	//// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-proof-of-possession
	//case POP:
	//	pop, err = PopProve[K, S](s.PrivateKey)
	//	if err != nil {
	//		return nil, nil, errs.WrapFailed(err, "could not produce proof of possession")
	//	}
	default:
		return nil, nil, errs.NewType("rogue key prevention scheme %d is not supported", s.scheme)
	}

	dst := DstSignatureBasicInG2
	point, err := coreSign(s.sk.d, message, dst, s.pairing.G2())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not sign")
	}

	signature := &Signature[P2, B2, S]{
		Value: point,
	}

	return signature, pop, nil
}
