package bip340

import (
	"crypto/subtle"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/hashing/bip340"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

const (
	auxSizeBytes = 32
)

var (
	curve    = k256.NewCurve()
	hashFunc = bip340.NewBip340HashChallenge
)

type PublicKey schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]

type PrivateKey struct {
	S *k256.Scalar
	PublicKey

	_ ds.Incomparable
}

type Signature = schnorr.Signature[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar]

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	serializedPublicKey := pk.A.ToAffineCompressed()[1:]
	return serializedPublicKey, nil
}

type Signer struct {
	privateKey *PrivateKey

	_ ds.Incomparable
}

func NewPrivateKey(scalar *k256.Scalar) (*PrivateKey, error) {
	if scalar == nil {
		return nil, errs.NewIsNil("secret is nil")
	}

	// 1. (implicit) Let d' = int(sk)
	dPrime := scalar

	// 2. Fail if d' = 0 or d' ≥ n (implicit)
	if dPrime.IsZero() {
		return nil, errs.NewIsZero("secret is zero")
	}

	// 3. Let P = d'⋅G
	public := curve.Generator().ScalarMul(dPrime)

	key := &PrivateKey{
		PublicKey: PublicKey{
			A: public.Clone(),
		},
		S: dPrime.Clone(),
	}

	return key, nil
}
func NewSigner(privateKey *PrivateKey) (*Signer, error) {
	if privateKey == nil {
		return nil, errs.NewIsNil("private key")
	}
	return &Signer{
		privateKey: privateKey,
	}, nil
}

func (signer *Signer) Sign(message, aux []byte, prng io.Reader) (*Signature, error) {
	if len(aux) == 0 && prng == nil {
		return nil, errs.NewFailed("must provide aux or PRNG")
	}
	if len(aux) == 0 {
		aux = make([]byte, auxSizeBytes)
		_, err := io.ReadFull(prng, aux)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "cannot generate nonce")
		}
	}
	if len(aux) != auxSizeBytes {
		return nil, errs.NewArgument("aux must have 32 bytes")
	}

	// 4. Let d = d' if P.y even, otherwise let d = n - d'
	bigP := curve.Generator().ScalarMul(signer.privateKey.S)
	d := negScalarIfPointYOdd(signer.privateKey.S, bigP)

	// 5. Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a).
	auxDigest, err := hashing.Hash(bip340.NewBip340HashAux, aux)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash failed")
	}
	t := make([]byte, len(auxDigest))
	if n := subtle.XORBytes(t, d.Bytes(), auxDigest); n != len(d.Bytes()) {
		return nil, errs.NewFailed("invalid scalar bytes length")
	}
	// 6. Let rand = hashBIP0340/nonce(t || bytes(P) || m).
	rand, err := hashing.Hash(bip340.NewBip340HashNonce, t, encodePoint(signer.privateKey.A), message)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash failed")
	}

	// 7. Let k' = int(rand) mod n.
	kPrime, err := curve.ScalarField().FromWideBytes(rand)
	if err != nil {
		return nil, errs.NewFailed("cannot set k'")
	}

	// 8. Fail if k' = 0
	if kPrime.IsZero() {
		return nil, errs.NewFailed("k' is invalid")
	}

	// 9. Let R = k'⋅G.
	bigR := curve.Generator().ScalarMul(kPrime)

	// 10. Let k = k' if R.x is even, otherwise let k = n - k', R = k ⋅ G
	// 11. Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
	e, err := taprootVariant.ComputeChallenge(hashFunc, bigR, bigP, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get e")
	}

	// 12. Let sig = (R, (k + ed) mod n)).
	s := taprootVariant.ComputeResponse(bigR, bigP, kPrime, signer.privateKey.S, e)
	signature := schnorr.NewSignature(taprootVariant, e, taprootVariant.ComputeNonceCommitment(bigR, bigR), s)

	// 13. If Verify(bytes(P), m, sig) returns failure, abort.
	verifier, err := taprootVariant.NewVerifierBuilder().
		WithPublicKey((*schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])(&signer.privateKey.PublicKey)).
		WithMessage(message).
		Build()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not build the verifier")
	}

	if err := verifier.Verify(signature); err != nil {
		return nil, errs.NewFailed("cannot create signature")
	}

	// 14. Return the signature sig.
	return signature, nil
}

func Verify(publicKey *PublicKey, signature *Signature, message []byte) error {
	if !publicKey.A.IsTorsionFree() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	v, err := taprootVariant.NewVerifierBuilder().
		WithPublicKey((*schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])(publicKey)).
		WithMessage(message).
		Build()
	if err != nil {
		return errs.WrapFailed(err, "could not build the verifier")
	}

	//nolint:wrapcheck // forward errors
	return v.Verify(signature)
}

//func VerifyBatch(publicKeys []*PublicKey, signatures []*Signature, messages [][]byte, prng io.Reader) (err error) {
//	if len(publicKeys) != len(signatures) || len(signatures) != len(messages) || len(signatures) == 0 {
//		return errs.NewArgument("length of publickeys, messages and signatures must be equal and greater than zero")
//	}
//	for _, publicKey := range publicKeys {
//		if !publicKey.A.IsTorsionFree() {
//			return errs.NewValidation("Public Key not in the prime subgroup")
//		}
//	}
//	// 1. Generate u-1 random integers a2...u in the range 1...n-1.
//	a := make([]*k256.Scalar, len(signatures))
//	a[0] = curve.ScalarField().One()
//	for i := 1; i < len(signatures); i++ {
//		for {
//			a[i], err = curve.ScalarField().Random(prng)
//			if err != nil {
//				return errs.WrapRandomSample(err, "cannot generate random scalar")
//			}
//			if !a[i].IsZero() {
//				break
//			}
//		}
//	}
//
//	// For i = 1 .. u:
//	left := curve.ScalarField().Zero()
//	ae := make([]*k256.Scalar, len(signatures))
//	bigR := make([]*k256.Point, len(signatures))
//	bigP := make([]*k256.Point, len(signatures))
//	for i, sig := range signatures {
//		// 2. Let P_i = lift_x(int(pki))
//		// 3. (implicit) Let r_i = int(sigi[0:32]); fail if ri ≥ p.
//		// 4. (implicit) Let s_i = int(sigi[32:64]); fail if si ≥ n.
//		bigP[i] = negPointIfPointYOdd(publicKeys[i].A)
//
//		// 5. Let ei = int(hashBIP0340/challenge(bytes(r_i) || bytes(P_i) || mi)) mod n.
//		e, err := taprootVariant.ComputeChallenge(hashFunc, sig.R, publicKeys[i].A, messages[i])
//		if err != nil {
//			return errs.WrapFailed(err, "invalid signature")
//		}
//
//		// 6. Let Ri = lift_x(ri); fail if lift_x(ri) fails.
//		bigR[i] = signatures[i].R
//
//		ae[i] = a[i].Mul(e)
//		left = left.Add(a[i].Mul(sig.S))
//	}
//
//	// 7. Fail if (s1 + a2s2 + ... + ausu)⋅G ≠ R1 + a2⋅R2 + ... + au⋅Ru + e1⋅P1 + (a2e2)⋅P2 + ... + (aueu)⋅Pu.
//	rightA, err := curve.MultiScalarMult(a, bigR)
//	if err != nil {
//		return errs.WrapFailed(err, "failed to multiply scalars and points")
//	}
//	rightB, err := curve.MultiScalarMult(ae, bigP)
//	if err != nil {
//		return errs.WrapFailed(err, "failed to multiply scalars and points")
//	}
//	right := rightA.Add(rightB)
//	if !curve.Generator().ScalarMul(left).Equal(right) {
//		return errs.NewVerification("signature is invalid")
//	}
//
//	// Return success iff no failure occurred before reaching this point.
//	return nil
//}

func encodePoint(p *k256.Point) []byte {
	return p.ToAffineCompressed()[1:]
}

// negScalarIfPointYOdd negates point if point.y is even.
func negPointIfPointYOdd(point *k256.Point) *k256.Point {
	if point.AffineY().IsOdd() {
		return point.Neg()
	} else {
		return point
	}
}

// negScalarIfPointYOdd negates scalar x if point.y is even.
func negScalarIfPointYOdd(x *k256.Scalar, point *k256.Point) *k256.Scalar {
	if point.AffineY().IsOdd() {
		return x.Neg()
	} else {
		return x
	}
}
