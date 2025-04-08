package bls

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// Warning: this is an internal method. We don't check if K and S are different subgroups.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coresign
func coreSign[P2 curves.Point[P2, B2, S], B2 fields.FiniteFieldElement[B2], S fields.PrimeFieldElement[S]](pk S, message []byte, dst string, dstCurve curves.Curve[P2, B2, S]) (P2, error) {
	var nilP2 P2

	// step 2.6.1
	q, err := dstCurve.HashWithDst(dst, message)
	if err != nil {
		return nilP2, errs.WrapHashing(err, "could not hash message")
	}

	// step 2.6.2
	r := q.ScalarMul(pk)
	return r, nil
}

func coreVerifyShortPublicKey[C1 curves.Curve[P1, B1, S], P1 curves.Point[P1, B1, S], B1 fields.FiniteFieldElement[B1], C2 curves.Curve[P2, B2, S], P2 curves.Point[P2, B2, S], B2 fields.FiniteFieldElement[B2], S fields.PrimeFieldElement[S], G groups.FiniteAbelianMultiplicativeGroup[GE, S], GE groups.FiniteAbelianMultiplicativeGroupElement[GE, S]](pk P1, message []byte, signature P2, dst string, pairing curves.Pairing[C1, P1, B1, C2, P2, B2, G, GE, S]) error {
	// Procedure:
	// 1. R = signature_to_point(signature)
	r := signature

	// 2. If R is INVALID, return INVALID
	// 3. If signature_subgroup_check(R) is INVALID, return INVALID
	if !r.IsTorsionFree() {
		return errs.NewFailed("invalid public key")
	}

	// 4. If KeyValidate(PK) is INVALID, return INVALID
	// 5. xP = pubkey_to_point(PK)
	xp := pk

	// 6. Q = hash_to_point(message)
	q, err := pairing.G2().HashWithDst(dst, message)
	if err != nil {
		return errs.WrapHashing(err, "could not hash message")
	}

	// 7. C1 = pairing(Q, xP)
	c1, err := pairing.Pair(xp, q)
	if err != nil {
		return errs.WrapHashing(err, "could not pair points")
	}

	// 8. C2 = pairing(R, P)
	c2, err := pairing.Pair(pairing.G1().Generator(), r)

	// 9. If C1 == C2, return VALID, else return INVALID
	if !c1.Equal(c2) {
		return errs.NewVerification("invalid signature")
	}

	return nil
}

// TODO: use multipairing
func coreVerifyLongPublicKey[C1 curves.Curve[P1, B1, S], P1 curves.Point[P1, B1, S], B1 fields.FiniteFieldElement[B1], C2 curves.Curve[P2, B2, S], P2 curves.Point[P2, B2, S], B2 fields.FiniteFieldElement[B2], S fields.PrimeFieldElement[S], G groups.FiniteAbelianMultiplicativeGroup[GE, S], GE groups.FiniteAbelianMultiplicativeGroupElement[GE, S]](pk P2, message []byte, signature P1, dst string, pairing curves.Pairing[C1, P1, B1, C2, P2, B2, G, GE, S]) error {
	// Procedure:
	// 1. R = signature_to_point(signature)
	r := signature

	// 2. If R is INVALID, return INVALID
	// 3. If signature_subgroup_check(R) is INVALID, return INVALID
	if !r.IsTorsionFree() {
		return errs.NewFailed("invalid public key")
	}

	// 4. If KeyValidate(PK) is INVALID, return INVALID
	// 5. xP = pubkey_to_point(PK)
	xp := pk

	// 6. Q = hash_to_point(message)
	q, err := pairing.G1().HashWithDst(dst, message)
	if err != nil {
		return errs.WrapHashing(err, "could not hash message")
	}

	// 7. C1 = pairing(Q, xP)
	c1, err := pairing.Pair(q, xp)
	if err != nil {
		return errs.WrapHashing(err, "could not pair points")
	}

	// 8. C2 = pairing(R, P)
	c2, err := pairing.Pair(r, pairing.G2().Generator())

	// 9. If C1 == C2, return VALID, else return INVALID
	if !c1.Equal(c2) {
		return errs.NewVerification("invalid signature")
	}

	return nil
}
