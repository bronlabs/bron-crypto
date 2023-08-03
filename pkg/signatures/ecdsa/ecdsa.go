package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"
	"fmt"
	"hash"
	"math/big"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/hashing"
)

type Signature struct {
	V *int
	R curves.Scalar
	S curves.Scalar
}

// Normalize normalizes the signature to a "low S" form. In ECDSA, signatures are
// of the form (r, s) where r and s are numbers lying in some finite
// field. Both (r, s) and (r, -s) are valid signatures of the same message
// so ECDSA does not have strong existential unforgeability
// We normalize to the low S form which ensures that the s value
// lies in the lower half of its range.
// See <https://en.bitcoin.it/wiki/BIP_0062#Low_S_values_in_signatures>
func (signature *Signature) Normalize() {
	if signature.S.Neg().BigInt().Cmp(signature.S.BigInt()) < 0 {
		signature.S = signature.S.Neg()
	}
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
// Note that due to signature malleability, for us v is always either 0 or 1 (= we consider non-normalized signatures as invalid)
func CalculateRecoveryId(bigR curves.Point) (int, error) {
	var rx, ry *big.Int
	if p, ok := bigR.(*curves.PointK256); ok {
		rx = p.X().BigInt()
		ry = p.Y().BigInt()
	} else if p, ok := bigR.(*curves.PointP256); ok {
		rx = p.X().BigInt()
		ry = p.Y().BigInt()
	} else {
		return -1, errs.NewInvalidCurve("unsupported curve %s", bigR.CurveName())
	}

	curve, err := curves.GetCurveByName(bigR.CurveName())
	if err != nil {
		return -1, errs.WrapInvalidCurve(err, "could not find curve (%s) of the R point", bigR.CurveName())
	}
	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return -1, errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
	}
	subGroupOrder := nativeCurve.Params().N

	var recoveryId int
	if ry.Bytes()[0]&1 == 0 {
		recoveryId = 0
	} else {
		recoveryId = 1
	}

	switch rx.Cmp(subGroupOrder) {
	case -1:
		break
	case 0:
		return -1, errs.NewFailed("x coordinate of the signature is equal to subGroupOrder")
	case 1:
		recoveryId += 2
		break
	default:
		return -1, errs.NewFailed("big int cmp failed, we should never be here")
	}

	return recoveryId, nil
}

// RecoverPublicKey recovers PublicKey (point on the curve) based od messageHash, public key and recovery id.
func RecoverPublicKey(signature *Signature, hashFunc func() hash.Hash, message []byte) (curves.Point, error) {
	if signature.V == nil {
		return nil, errs.NewIsNil("no recovery id")
	}

	curve, err := curves.GetCurveByName(signature.R.CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not find curve (%s) of the R point", signature.R.CurveName())
	}
	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
	}
	subGroupOrder := nativeCurve.Params().N

	// Calculate point R = (x1, x2) where
	//  x1 = r if (v & 2) == 0 or (r + n) if (v & 2) == 1
	//  y1 = value such that the curve equation is satisfied, y1 should be even when (v & 1) == 0, odd otherwise
	rx := signature.R.BigInt()
	if (*signature.V & 2) != 0 {
		rx = new(big.Int).Add(rx, subGroupOrder)
	}
	rxBytes := rx.Bytes()
	if len(rxBytes) < 32 {
		rxBytes = append(make([]byte, 32-len(rxBytes)), rxBytes...)
	}
	ryCompressed := []byte{byte(2)}
	if (*signature.V & 1) != 0 {
		ryCompressed[0]++
	}
	affine := append(ryCompressed[:], rxBytes...)
	bigR, err := curve.Point.FromAffineCompressed(affine[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate R")
	}

	// Calculate point Q (public key)
	//  Q = r^(-1)(sR - zG)
	messageHash, err := hashing.Hash(hashFunc, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash message")
	}
	zInt, err := HashToInt(messageHash, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get int from hash")
	}
	z, err := curve.NewScalar().SetBytes(zInt.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate z")
	}
	rInv, err := signature.R.Invert()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate inverse of R.x")
	}
	publicKey := (bigR.Mul(signature.S).Sub(curve.ScalarBaseMult(z))).Mul(rInv)

	return publicKey, nil
}

func Verify(signature *Signature, hashFunc func() hash.Hash, publicKey curves.Point, message []byte) error {
	curve, err := curves.GetCurveByName(publicKey.CurveName())
	if err != nil {
		return errs.WrapFailed(err, "could not get curve")
	}
	if curve.Name != curves.K256Name && curve.Name != curves.P256Name {
		return errs.NewFailed("curve is not supported")
	}
	if !publicKey.IsOnCurve() {
		return errs.NewVerificationFailed("public key is not on curve")
	}
	if publicKey.IsIdentity() {
		return errs.NewIsIdentity("public key is identity")
	}
	if signature.V != nil {
		recoveredPublicKey, err := RecoverPublicKey(signature, hashFunc, message)
		if err != nil {
			return errs.WrapFailed(err, "signature has a recovery id but public key could not be recovered")
		}
		fmt.Println("!!!!", *signature.V)
		if !recoveredPublicKey.Equal(publicKey) {
			fmt.Println(recoveredPublicKey.ToAffineCompressed())
			fmt.Println(publicKey.ToAffineCompressed())
			return errs.NewVerificationFailed("incorrect recovery id")
		}
	}

	messageDigest, err := hashing.Hash(hashFunc, message)
	if err != nil {
		return errs.WrapFailed(err, "could not produce ")
	}

	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
	}

	x, y := getPointCoordinates(publicKey)
	nativePublicKey := &nativeEcdsa.PublicKey{
		Curve: nativeCurve,
		X:     x, Y: y,
	}
	if ok := nativeEcdsa.Verify(nativePublicKey, messageDigest, signature.R.BigInt(), signature.S.BigInt()); !ok {
		return errs.NewVerificationFailed("signature verification failed")
	}
	return nil
}

func HashToInt(hash []byte, curve *curves.Curve) (*big.Int, error) {
	ecdsaCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
	}
	order := ecdsaCurve.Params().N
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get curve order")
	}
	orderBits := order.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret, nil
}

func getPointCoordinates(point curves.Point) (x *big.Int, y *big.Int) {
	affine := point.ToAffineUncompressed()
	return new(big.Int).SetBytes(affine[1:33]), new(big.Int).SetBytes(affine[33:65])
}
