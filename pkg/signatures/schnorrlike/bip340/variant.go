package bip340

import (
	"crypto/subtle"
	"hash"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/hashing/bip340"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/errs-go/errs"
)

// VariantType identifies this as the BIP-340 Schnorr variant.
const VariantType schnorrlike.VariantType = "bip340"

var (
	_ schnorrlike.Variant[*GroupElement, *Scalar, Message]         = (*Variant)(nil)
	_ tschnorr.MPCFriendlyVariant[*GroupElement, *Scalar, Message] = (*Variant)(nil)
)

// Variant implements BIP-340 specific signing behaviour.
// It handles the deterministic nonce derivation, even-y constraints,
// and tagged hashing required by BIP-340.
type Variant struct {
	sk         *PrivateKey        // Private key for deterministic nonce derivation
	Aux        [AuxSizeBytes]byte // Auxiliary randomness for nonce derivation
	msg        Message            // Message being signed (needed for nonce computation)
	adjustedSk *Scalar            // Private key d adjusted for P.y parity (negated if P.y is odd)
}

// Type returns the variant identifier "bip340".
func (*Variant) Type() schnorrlike.VariantType {
	return VariantType
}

// HashFunc returns the BIP-340 tagged hash function for challenge computation.
// Uses SHA-256 with the tag "BIP0340/challenge" for domain separation.
func (*Variant) HashFunc() func() hash.Hash {
	return bip340.NewBip340HashChallenge
}

// ComputeNonceCommitment implements BIP-340 deterministic nonce derivation.
//
// The nonce k is derived as:
//  1. t = d XOR H_aux(aux) where d is the (possibly negated) private key
//  2. rand = H_nonce(t || P || m)
//  3. k' = rand mod n
//  4. If R.y is odd, k = n - k' (to ensure R has even y)
//
// This deterministic derivation prevents nonce reuse vulnerabilities while
// the auxiliary randomness provides side-channel protection.
func (v *Variant) ComputeNonceCommitment() (R *GroupElement, k *Scalar, err error) {
	if v.sk == nil || v.msg == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("need both private key and message")
	}
	g := k256.NewCurve().Generator()
	f := k256.NewScalarField()
	// 1. Let d' = int(sk)
	dPrime := v.sk.Value()
	// 2. Fail if d' = 0 or d' ≥ n
	if dPrime.IsZero() {
		return nil, nil, ErrFailed.WithMessage("d' is invalid")
	}
	// 3. Let P = d'⋅G
	bigP := g.ScalarMul(v.sk.Value())
	// 4. Let d = d' if P.y even, otherwise let d = n - d'
	d := dPrime
	py, err := bigP.AffineY()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compute y")
	}
	if py.IsOdd() {
		d = dPrime.Neg()
	}
	// Store the adjusted private key for use in ComputeResponse
	v.adjustedSk = d
	// 5. Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a).
	auxDigest, err := hashing.Hash(bip340.NewBip340HashAux, v.Aux[:])
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("hash failed")
	}
	t := make([]byte, len(auxDigest))
	if n := subtle.XORBytes(t, d.Bytes(), auxDigest); n != len(d.Bytes()) {
		return nil, nil, ErrFailed.WithMessage("invalid scalar bytes length")
	}
	// 6. Let rand = hashBIP0340/nonce(t || bytes(P) || m).
	rand, err := hashing.Hash(
		bip340.NewBip340HashNonce, t, encodePoint(bigP), v.msg,
	)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("hash failed")
	}

	// 7. Let k' = int(rand) mod n.
	kPrime, err := f.FromWideBytes(rand)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot set k'")
	}

	// 8. Fail if k' = 0
	if kPrime.IsZero() {
		return nil, nil, ErrFailed.WithMessage("k' is invalid")
	}

	// 9. Let R = k'⋅G.
	bigR := g.ScalarMul(kPrime)
	// 10. Let k = k' if R.y is even, otherwise let k = n - k', R = k ⋅ G
	k = kPrime
	ry, err := bigR.AffineY()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compute y")
	}
	if ry.IsOdd() {
		k = kPrime.Neg()
		bigR = g.ScalarMul(k)
	}
	return bigR, k, nil
}

// ComputeChallenge computes the BIP-340 challenge using tagged hashing.
// e = H_challenge(R.x || P || m) mod n
//
// The challenge hash uses SHA-256 with the tag "BIP0340/challenge".
// R and P are encoded as 32-byte x-coordinates (x-only encoding).
func (v *Variant) ComputeChallenge(nonceCommitment, publicKeyValue *GroupElement, message Message) (*Scalar, error) {
	// 11. Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
	roinput := slices.Concat(
		nonceCommitment.ToCompressed()[1:],
		publicKeyValue.ToCompressed()[1:],
		message,
	)

	e, err := schnorrlike.MakeGenericChallenge(k256.NewScalarField(), v.HashFunc(), false, roinput)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("hash failed")
	}
	return e, nil
}

// ComputeResponse computes the BIP-340 signature response: s = k + e·d mod n.
// Uses the adjusted private key d (negated if P.y was odd during nonce commitment).
func (v *Variant) ComputeResponse(privateKeyValue, nonce, challenge *Scalar) (*Scalar, error) {
	if privateKeyValue == nil || nonce == nil || challenge == nil {
		return nil, ErrInvalidArgument.WithMessage("arguments are nil")
	}
	// Use the adjusted private key if available (from ComputeNonceCommitment)
	// This ensures we use d (not d') when P.y is odd
	adjustedPrivateKey := privateKeyValue
	if v.adjustedSk != nil {
		adjustedPrivateKey = v.adjustedSk
	}
	s, err := schnorrlike.ComputeGenericResponse(adjustedPrivateKey, nonce, challenge, false)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute BIP340 response")
	}
	// 12. Let sig = (R, (k + ed) mod n)).
	return s, nil
}

// SerializeSignature encodes the signature to 64 bytes: (R.x || s).
func (*Variant) SerializeSignature(signature *Signature) ([]byte, error) {
	return SerializeSignature(signature)
}

// Clone creates a deep copy of the variant.
func (v *Variant) Clone() *Variant {
	out := &Variant{
		sk:         nil,
		Aux:        v.Aux,
		msg:        nil,
		adjustedSk: nil,
	}
	if v.sk != nil {
		out.sk = v.sk.Clone()
	}
	if v.msg != nil {
		copy(out.msg, v.msg)
	}
	if v.adjustedSk != nil {
		out.adjustedSk = v.adjustedSk.Clone()
	}
	return out
}

// ============ MPC Methods ============.
//
// These methods support threshold/MPC Schnorr signing with BIP-340.
// BIP-340 requires R and P to have even y-coordinates, which requires
// special handling in distributed signing protocols.

var _ tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, Message] = (*Variant)(nil)

// CorrectAdditiveSecretShareParity adjusts a secret share for BIP-340's even-y requirement.
//
// In threshold signing, each party holds a share of the private key x.
// If the aggregate public key P = x·G has odd y, BIP-340 requires using -x instead.
// This method negates the share if P.y is odd, ensuring all parties use
// consistent (negated) shares when P.y is odd.
func (*Variant) CorrectAdditiveSecretShareParity(publicKey *PublicKey, share *additive.Share[*k256.Scalar]) (*additive.Share[*k256.Scalar], error) {
	if publicKey == nil || share == nil {
		return nil, ErrInvalidArgument.WithMessage("public key or secret share is nil")
	}
	out := share.Clone()
	pky, err := publicKey.Value().AffineY()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute y")
	}
	if pky.IsOdd() {
		// If the public key is odd, we need to negate the additive share
		// to ensure that the parity of the nonce commitment is correct.
		out, _ = additive.NewShare(share.ID(), share.Value().Neg(), nil)
	}
	return out, nil
}

// CorrectPublicKeyShareParity applies the same parity correction to a public key share
// that CorrectAdditiveSecretShareParity applies to private key shares. This is needed
// for partial signature verification where the public key share must be corrected
// based on the aggregate public key's Y coordinate parity.
func (*Variant) CorrectPublicKeyShareParity(aggregatePublicKey *PublicKey, share *k256.Point) (*k256.Point, error) {
	if aggregatePublicKey == nil || share == nil {
		return nil, ErrInvalidArgument.WithMessage("aggregate public key or share is nil")
	}
	pky, err := aggregatePublicKey.Value().AffineY()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute y")
	}
	if pky.IsOdd() {
		// If the aggregate public key has odd Y, negate the share to match
		// the correction applied to private key shares during signing.
		return share.Neg(), nil
	}
	return share, nil
}

// CorrectPartialNonceParity adjusts a partial nonce for BIP-340's even-y requirement.
//
// In threshold signing, the aggregate nonce commitment R must have even y.
// After all parties contribute their nonce commitments and the aggregate R is known,
// if R.y is odd, each party must negate their partial nonce k_i.
// This ensures the aggregate response s = Σk_i + e·Σx_i uses the correct nonces.
func (*Variant) CorrectPartialNonceParity(nonceCommitment *k256.Point, k *k256.Scalar) (*k256.Point, *k256.Scalar, error) {
	if nonceCommitment == nil || k == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("nonce commitment or k is nil")
	}
	correctedK := k.Clone()
	y, err := nonceCommitment.AffineY()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compute y")
	}
	if y.IsOdd() {
		// If the nonce commitment is odd, we need to negate k to ensure that the parity is correct.
		correctedK = correctedK.Neg()
	}
	correctedR := k256.NewCurve().ScalarBaseOp(correctedK)
	return correctedR, correctedK, nil
}
