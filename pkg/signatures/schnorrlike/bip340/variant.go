package bip340

import (
	"crypto/subtle"
	"hash"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/hashing/bip340"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

const VariantType schnorrlike.VariantType = "bip340"

var (
	_ schnorrlike.Variant[*GroupElement, *Scalar, Message]         = (*Variant)(nil)
	_ tschnorr.MPCFriendlyVariant[*GroupElement, *Scalar, Message] = (*Variant)(nil)
)

type Variant struct {
	sk  *PrivateKey
	Aux [AuxSizeBytes]byte
	msg Message
}

func (*Variant) Type() schnorrlike.VariantType {
	return VariantType
}
func (*Variant) HashFunc() func() hash.Hash {
	return bip340.NewBip340HashChallenge
}

func (v *Variant) ComputeNonceCommitment() (*GroupElement, *Scalar, error) {
	if v.sk == nil || v.msg == nil {
		return nil, nil, errs.NewIsNil("need both private key and message")
	}
	g := k256.NewCurve().Generator()
	f := k256.NewScalarField()
	// 1. Let d' = int(sk)
	dPrime := v.sk.Value()
	// 2. Fail if d' = 0 or d' ≥ n
	if dPrime.IsZero() {
		return nil, nil, errs.NewFailed("d' is invalid")
	}
	// 3. Let P = d'⋅G
	bigP := g.ScalarMul(v.sk.Value())
	// 4. Let d = d' if P.y even, otherwise let d = n - d'
	d := dPrime
	if bigP.AffineY().IsOdd() {
		d = dPrime.Neg()
	}
	// 5. Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a).
	auxDigest, err := hashing.Hash(bip340.NewBip340HashAux, v.Aux[:])
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "hash failed")
	}
	t := make([]byte, len(auxDigest))
	if n := subtle.XORBytes(t, d.Bytes(), auxDigest); n != len(d.Bytes()) {
		return nil, nil, errs.NewFailed("invalid scalar bytes length")
	}
	// 6. Let rand = hashBIP0340/nonce(t || bytes(P) || m).
	rand, err := hashing.Hash(
		bip340.NewBip340HashNonce, t, encodePoint(bigP), v.msg,
	)
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "hash failed")
	}

	// 7. Let k' = int(rand) mod n.
	kPrime, err := f.FromWideBytes(rand)
	if err != nil {
		return nil, nil, errs.NewFailed("cannot set k'")
	}

	// 8. Fail if k' = 0
	if kPrime.IsZero() {
		return nil, nil, errs.NewFailed("k' is invalid")
	}

	// 9. Let R = k'⋅G.
	bigR := g.ScalarMul(kPrime)
	// 10. Let k = k' if R.y is even, otherwise let k = n - k', R = k ⋅ G
	k := kPrime
	if bigR.AffineY().IsOdd() {
		k = kPrime.Neg()
		bigR = g.ScalarMul(k)
	}
	return bigR, k, nil
}

func (v *Variant) ComputeChallenge(nonceCommitment, publicKeyValue *GroupElement, message Message) (*Scalar, error) {
	// 11. Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
	roinput := slices.Concat(
		nonceCommitment.ToCompressed()[1:],
		publicKeyValue.ToCompressed()[1:],
		message,
	)

	e, err := schnorrlike.MakeGenericChallenge(k256.NewScalarField(), v.HashFunc(), false, roinput)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash failed")
	}
	return e, nil
}

func (*Variant) ComputeResponse(privateKeyValue, nonce, challenge *Scalar) (*Scalar, error) {
	if privateKeyValue == nil || nonce == nil || challenge == nil {
		return nil, errs.NewIsNil("arguments")
	}
	// 12. Let sig = (R, (k + ed) mod n)).
	return nonce.Add(challenge.Mul(privateKeyValue)), nil
}

func (*Variant) SerializeSignature(signature *Signature) ([]byte, error) {
	return SerializeSignature(signature)
}

func (*Variant) NonceIsFunctionOfMessage() bool {
	return true
}

func (v *Variant) Clone() *Variant {
	out := &Variant{
		Aux: v.Aux,
	}
	if v.sk != nil {
		out.sk = v.sk.Clone()
	}
	if v.msg != nil {
		copy(out.msg, v.msg)
	}
	return out
}

// ============ MPC Methods ============

var _ tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, Message] = (*Variant)(nil)

func (v *Variant) CorrectAdditiveSecretShareParity(publicKey *PublicKey, share *additive.Share[*k256.Scalar]) (*additive.Share[*k256.Scalar], error) {
	if publicKey == nil || share == nil {
		return nil, errs.NewIsNil("public key or secret share is nil")
	}
	out := share.Clone()
	if publicKey.Value().AffineY().IsOdd() {
		// If the public key is odd, we need to negate the additive share
		// to ensure that the parity of the nonce commitment is correct.
		out, _ = additive.NewShare(share.ID(), share.Value().Neg(), nil)
	}
	return out, nil
}

func (v *Variant) CorrectPartialNonceParity(nonceCommitment *k256.Point, k *k256.Scalar) (*k256.Point, *k256.Scalar, error) {
	if nonceCommitment == nil || k == nil {
		return nil, nil, errs.NewIsNil("nonce commitment or k is nil")
	}
	correctedK := k.Clone()
	if nonceCommitment.AffineY().IsOdd() {
		// If the nonce commitment is odd, we need to negate k to ensure that the parity is correct.
		correctedK = correctedK.Neg()
	}
	correctedR := k256.NewCurve().ScalarBaseOp(correctedK)
	return correctedR, correctedK, nil
}
