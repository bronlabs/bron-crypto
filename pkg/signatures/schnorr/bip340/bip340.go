package bip340

import (
	"crypto/subtle"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/bip340"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

const (
	auxSizeBytes = 32
)

type PublicKey = schnorr.PublicKey

type PrivateKey = schnorr.PrivateKey

// Signature BIP-340 signature.
type Signature = schnorr.Signature

type Signer struct {
	privateKey *PrivateKey

	_ types.Incomparable
}

func NewPrivateKey(scalar curves.Scalar) (*PrivateKey, error) {
	if scalar == nil {
		return nil, errs.NewIsNil("secret is nil")
	}

	curve := k256.NewCurve()

	// 1. (implicit) Let d' = int(sk)
	dPrime := scalar
	if dPrime.ScalarField().Name() != curve.Name() {
		return nil, errs.NewFailed("unsupported curve")
	}

	// 2. Fail if d' = 0 or d' ≥ n (implicit)
	if dPrime.IsZero() {
		return nil, errs.NewIsNil("secret is zero")
	}

	// 3. Let P = d'⋅G
	public := curve.ScalarBaseMult(dPrime)

	return &PrivateKey{
		PublicKey: PublicKey{
			A: public.Clone(),
		},
		S: dPrime.Clone(),
	}, nil
}
func NewSigner(privateKey *PrivateKey) *Signer {
	return &Signer{
		privateKey: privateKey,
	}
}

func (signer *Signer) Sign(message, aux []byte, prng io.Reader) (*Signature, error) {
	if len(aux) == 0 && prng == nil {
		return nil, errs.NewFailed("must provide aux or PRNG")
	}
	if len(aux) == 0 {
		aux = make([]byte, auxSizeBytes)
		_, err := prng.Read(aux)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot generate nonce")
		}
	}
	if len(aux) != auxSizeBytes {
		return nil, errs.NewInvalidArgument("aux must have 32 bytes")
	}
	curve := signer.privateKey.S.ScalarField().Curve()

	// 4. Let d = d' if P.y even, otherwise let d = n - d'
	bigP := curve.ScalarBaseMult(signer.privateKey.S)
	d := negScalarIfPointYOdd(signer.privateKey.S, bigP)

	// 5. Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a).
	auxDigest, err := hashing.Hash(bip340.NewBip340HashAux, aux)
	if err != nil {
		return nil, errs.WrapFailed(err, "hash failed")
	}
	t := make([]byte, len(auxDigest))
	if n := subtle.XORBytes(t, d.Bytes(), auxDigest); n != len(d.Bytes()) {
		return nil, errs.NewFailed("invalid scalar bytes length")
	}
	// 6. Let rand = hashBIP0340/nonce(t || bytes(P) || m).
	rand, err := hashing.Hash(bip340.NewBip340HashNonce, t, encodePoint(signer.privateKey.A), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "hash failed")
	}

	// 7. Let k' = int(rand) mod n.
	kPrime, err := curve.Scalar().SetBytes(rand)
	if err != nil {
		return nil, errs.NewFailed("cannot set k'")
	}

	// 8. Fail if k' = 0
	if kPrime.IsZero() {
		return nil, errs.NewFailed("k' is invalid")
	}

	// 9. Let R = k'⋅G.
	bigR := curve.ScalarBaseMult(kPrime)

	// 10. Let k = k' if R.x is even, otherwise let k = n - k'
	k := negScalarIfPointYOdd(kPrime, bigR)
	// recalculate R - additional step since we deal with full points i.e. (x, y)
	bigR = curve.ScalarBaseMult(k)

	// 11. Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
	e, err := calcChallenge(bigR, signer.privateKey.A, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get e")
	}

	// 12. Let sig = (R, (k + ed) mod n)).
	s := k.Add(e.Mul(d))
	signature := &Signature{
		R: bigR,
		S: s,
	}

	// 13. If Verify(bytes(P), m, sig) returns failure, abort.
	err = Verify(&signer.privateKey.PublicKey, signature, message)
	if err != nil {
		return nil, errs.NewFailed("cannot create signature")
	}

	// 14. Return the signature sig.
	return signature, nil
}

func Verify(publicKey *PublicKey, signature *Signature, message []byte) error {
	if publicKey.A.Curve().Name() != k256.Name || signature.R.Curve().Name() != k256.Name || signature.S.ScalarField().Curve().Name() != k256.Name {
		return errs.NewInvalidArgument("curve not supported")
	}
	if signature.R == nil || signature.S == nil || signature.R.IsIdentity() || signature.S.IsZero() {
		return errs.NewVerificationFailed("some signature elements are nil/zero")
	}
	curve := k256.NewCurve()

	// 1. Let P = lift_x(int(pk)).
	// 2. (implicit) Let r = int(sig[0:32]); fail if r ≥ p.
	// 3. (implicit) Let s = int(sig[32:64]); fail if s ≥ n.
	bigP := negPointIfPointYOdd(publicKey.A)

	// 4. Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
	e, err := calcChallenge(signature.R, bigP, message)
	if err != nil {
		return errs.WrapVerificationFailed(err, "invalid signature")
	}

	// 5. Let R = s⋅G - e⋅P.
	bigR := curve.ScalarBaseMult(signature.S).Sub(bigP.Mul(e))

	// 6. Fail if is_infinite(R).
	// 7. Fail if not has_even_y(R).
	// 8. Fail if x(R) ≠ r.
	if bigR.IsIdentity() || !bigR.AffineY().IsEven() || signature.R.AffineX().Cmp(bigR.AffineX()) != 0 {
		return errs.NewVerificationFailed("signature is invalid")
	}

	return nil
}

func VerifyBatch(publicKeys []*PublicKey, signatures []*Signature, messages [][]byte, prng io.Reader) (err error) {
	curve := k256.NewCurve()

	if len(publicKeys) != len(signatures) || len(signatures) != len(messages) || len(signatures) == 0 {
		return errs.NewInvalidArgument("length of publickeys, messages and signatures must be equal and greater than zero")
	}

	// 1. Generate u-1 random integers a2...u in the range 1...n-1.
	a := make([]curves.Scalar, len(signatures))
	a[0] = curve.ScalarField().One()
	for i := 1; i < len(signatures); i++ {
		for {
			a[i], err = curve.ScalarField().Random(prng)
			if err != nil {
				return errs.WrapRandomSampleFailed(err, "cannot generate random scalar")
			}
			if !a[i].IsZero() {
				break
			}
		}
	}

	// For i = 1 .. u:
	left := curve.ScalarField().Zero()
	ae := make([]curves.Scalar, len(signatures))
	bigR := make([]curves.Point, len(signatures))
	bigP := make([]curves.Point, len(signatures))
	for i, sig := range signatures {
		// 2. Let P_i = lift_x(int(pki))
		// 3. (implicit) Let r_i = int(sigi[0:32]); fail if ri ≥ p.
		// 4. (implicit) Let s_i = int(sigi[32:64]); fail if si ≥ n.
		bigP[i] = negPointIfPointYOdd(publicKeys[i].A)

		// 5. Let ei = int(hashBIP0340/challenge(bytes(r_i) || bytes(P_i) || mi)) mod n.
		e, err := calcChallenge(sig.R, publicKeys[i].A, messages[i])
		if err != nil {
			return errs.WrapVerificationFailed(err, "invalid signature")
		}

		// 6. Let Ri = lift_x(ri); fail if lift_x(ri) fails.
		bigR[i] = signatures[i].R

		ae[i] = a[i].Mul(e)
		left = left.Add(a[i].Mul(sig.S))
	}

	// 7. Fail if (s1 + a2s2 + ... + ausu)⋅G ≠ R1 + a2⋅R2 + ... + au⋅Ru + e1⋅P1 + (a2e2)⋅P2 + ... + (aueu)⋅Pu.
	rightA, err := curve.MultiScalarMult(a, bigR)
	if err != nil {
		return errs.WrapFailed(err, "failed to multiply scalars and points")
	}
	rightB, err := curve.MultiScalarMult(ae, bigP)
	if err != nil {
		return errs.WrapFailed(err, "failed to multiply scalars and points")
	}
	right := rightA.Add(rightB)
	if !curve.ScalarBaseMult(left).Equal(right) {
		return errs.NewVerificationFailed("signature is invalid")
	}

	// Return success iff no failure occurred before reaching this point.
	return nil
}

func calcChallenge(bigR, bigP curves.Point, message []byte) (curves.Scalar, error) {
	eBytes, err := hashing.Hash(bip340.NewBip340HashChallenge, encodePoint(bigR), encodePoint(bigP), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge")
	}
	e, err := bigR.Curve().Scalar().SetBytes(eBytes)
	if err != nil {
		return nil, errs.WrapVerificationFailed(err, "cannot create challenge")
	}

	return e, nil
}

func encodePoint(p curves.Point) []byte {
	return p.ToAffineCompressed()[1:]
}

// negScalarIfPointYOdd negates point if point.y is even.
func negPointIfPointYOdd(point curves.Point) curves.Point {
	if point.AffineY().IsOdd() {
		return point.Neg()
	} else {
		return point
	}
}

// negScalarIfPointYOdd negates scalar x if point.y is even.
func negScalarIfPointYOdd(x curves.Scalar, point curves.Point) curves.Scalar {
	if point.AffineY().IsOdd() {
		return x.Neg()
	} else {
		return x
	}
}
