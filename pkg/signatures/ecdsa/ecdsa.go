package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"
	"hash"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

type Signature struct {
	V *int
	R curves.Scalar
	S curves.Scalar

	_ ds.Incomparable
}

// Normalise normalises the signature to a "low S" form. In ECDSA, signatures are
// of the form (r, s) where r and s are numbers lying in some finite
// field. Both (r, s) and (r, -s) are valid signatures of the same message
// so ECDSA does not have strong existential unforgeability
// We normalise to the low S form which ensures that the s value
// lies in the lower half of its range.
// See <https://en.bitcoin.it/wiki/BIP_0062#Low_S_values_in_signatures>
func (signature *Signature) Normalise() {
	if !signature.IsNormalized() {
		signature.S = signature.S.Neg()
		if signature.V != nil {
			v := *signature.V ^ 1
			signature.V = &v
		}
	}
}

func (signature *Signature) IsNormalized() bool {
	return signature.S.Nat().Big().Cmp(signature.S.Neg().Nat().Big()) <= 0
}

// CalculateRecoveryId calculates recoveryId
// V is not part of the ECDSA standard and is a bitcoin-concept that allows recovery of the public key from the signature,
// because you want to verify the signature coming from an "address", not a public key.
// The values of V are:
//
//	v = 0 if R.y is even (= quadratic residue mod q)
//	v = 1 if R.y is not even
//	v = v if R.x is less than subgroup order
//	v = v + 2 if R.x is greater than subgroup order (but less than the field order which it always will be)
//
// Definition of recovery id described here: https://en.bitcoin.it/wiki/Message_signing
// Recovery process itself described in 4.1.6: http://www.secg.org/sec1-v2.pdf
// Note that V here is the same as recovery Id is EIP-155.
// Note that due to signature malleability, for us v is always either 0 or 1 (= we consider non-normalised signatures as invalid).
func CalculateRecoveryId(bigR curves.Point) (int, error) {
	var rx, ry *saferith.Nat

	//nolint:gocritic // below is not a switch
	if p, ok := bigR.(*k256.Point); ok {
		rx = p.AffineX().Nat()
		ry = p.AffineY().Nat()
	} else if p, ok := bigR.(*p256.Point); ok {
		rx = p.AffineX().Nat()
		ry = p.AffineY().Nat()
	} else {
		return -1, errs.NewCurve("unsupported curve %s", bigR.Curve().Name())
	}

	curve := bigR.Curve()
	subGroupOrder := curve.SubGroupOrder()

	var recoveryId int
	if ry.Byte(0)&0b1 == 0 {
		recoveryId = 0
	} else {
		recoveryId = 1
	}

	b, _, _ := rx.Cmp(subGroupOrder.Nat())
	if b != 0 {
		recoveryId += 2
	}

	return recoveryId, nil
}

// RecoverPublicKey recovers PublicKey (point on the curve) based od messageHash, public key and recovery id.
func RecoverPublicKey(signature *Signature, hashFunc func() hash.Hash, message []byte) (curves.Point, error) {
	if signature.V == nil {
		return nil, errs.NewIsNil("no recovery id")
	}

	curve := signature.R.ScalarField().Curve()
	// Calculate point R = (x1, x2) where
	//  x1 = r if (v & 2) == 0 or (r + n) if (v & 2) == 1
	//  y1 = value such that the curve equation is satisfied, y1 should be even when (v & 1) == 0, odd otherwise
	rx := signature.R.Nat()
	if (*signature.V & 2) != 0 {
		rx = new(saferith.Nat).Add(rx, curve.SubGroupOrder().Nat(), curve.BaseField().Order().BitLen())
	}
	rxBytes := rx.Bytes()
	if len(rxBytes) < 32 {
		rxBytes = append(make([]byte, 32-len(rxBytes)), rxBytes...)
	}
	ryCompressed := []byte{byte(2)}
	if (*signature.V & 1) != 0 {
		ryCompressed[0]++
	}
	affine := append(ryCompressed, rxBytes...)
	bigR, err := curve.Point().FromAffineCompressed(affine)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate R")
	}

	// Calculate point Q (public key)
	//  Q = r^(-1)(sR - zG)
	messageHash, err := hashing.Hash(hashFunc, message)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash message")
	}
	zInt, err := HashToInt(messageHash, curve)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot get int from hash")
	}
	var zIntBytes [32]byte
	zInt.FillBytes(zIntBytes[:])
	z, err := curve.Scalar().SetBytes(zIntBytes[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate z")
	}
	rInv := signature.R.MultiplicativeInverse()
	publicKey := (bigR.Mul(signature.S).Sub(curve.ScalarBaseMult(z))).Mul(rInv)

	return publicKey, nil
}

func Verify(signature *Signature, hashFunc func() hash.Hash, publicKey curves.Point, message []byte) error {
	curve := publicKey.Curve()
	if curve.Name() != k256.Name && curve.Name() != p256.Name {
		return errs.NewFailed("curve is not supported")
	}
	if publicKey == nil {
		return errs.NewIsNil("public key")
	}
	if publicKey.IsIdentity() {
		return errs.NewIsIdentity("public key is identity")
	}
	if signature == nil {
		return errs.NewIsNil("signature")
	}
	if signature.V != nil {
		recoveredPublicKey, err := RecoverPublicKey(signature, hashFunc, message)
		if err != nil {
			return errs.WrapFailed(err, "signature has a recovery id but public key could not be recovered")
		}
		if !recoveredPublicKey.Equal(publicKey) {
			return errs.NewVerification("incorrect recovery id")
		}
	}

	messageDigest, err := hashing.Hash(hashFunc, message)
	if err != nil {
		return errs.WrapHashing(err, "could not produce message digest")
	}

	nativeCurve, err := curveutils.ToGoEllipticCurve(curve)
	if err != nil {
		return errs.WrapCurve(err, "krypton curve cannot be converted to Go's elliptic curve representation")
	}

	nativePublicKey := &nativeEcdsa.PublicKey{
		Curve: nativeCurve,
		X:     publicKey.AffineX().Nat().Big(), Y: publicKey.AffineY().Nat().Big(),
	}
	if ok := nativeEcdsa.Verify(nativePublicKey, messageDigest, signature.R.Nat().Big(), signature.S.Nat().Big()); !ok {
		return errs.NewVerification("signature verification failed")
	}
	return nil
}

func HashToInt(digest []byte, curve curves.Curve) (*saferith.Nat, error) {
	orderBytes := len(curve.SubGroupOrder().Bytes())
	if len(digest) > orderBytes {
		digest = digest[:orderBytes]
	}

	ret := new(saferith.Nat).SetBytes(digest)
	excess := (len(digest) - orderBytes) * 8
	if excess > 0 {
		ret.Rsh(ret, uint(excess), curve.SubGroupOrder().BitLen())
	}
	return ret, nil
}
