package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"math/big"
)

type Signature struct {
	R curves.Scalar
	S curves.Scalar
}

type RecoveryId struct {
	V int
}

type SignatureExt struct {
	Signature
	RecoveryId
}

type PublicKey struct {
	Q curves.Point
}

type SecretKey struct {
	PublicKey
	D curves.Scalar
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
func CalculateRecoveryId(bigR curves.Point) (*RecoveryId, error) {
	var rx, ry *big.Int
	if p, ok := bigR.(*curves.PointK256); ok {
		rx = p.X().BigInt()
		ry = p.Y().BigInt()
	} else if p, ok := bigR.(*curves.PointP256); ok {
		rx = p.X().BigInt()
		ry = p.Y().BigInt()
	} else {
		return nil, errs.NewInvalidCurve("unsupported curve %s", bigR.CurveName())
	}

	curve, err := curves.GetCurveByName(bigR.CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not find curve (%s) of the R point", bigR.CurveName())
	}
	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
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
		return nil, errs.NewFailed("x coordinate of the signature is equal to subGroupOrder")
	case 1:
		recoveryId += 2
		break
	default:
		return nil, errs.NewFailed("big int cmp failed, we should never be here")
	}

	return &RecoveryId{V: recoveryId}, nil
}

func (signatureExt *SignatureExt) VerifyHash(publicKey *PublicKey, messageHash []byte) bool {
	if ok := signatureExt.VerifyHashWithPublicKey(publicKey, messageHash); !ok {
		return false
	}

	if ok := signatureExt.VerifyHashWithRecoveryId(&signatureExt.RecoveryId, messageHash); !ok {
		return false
	}

	return true
}

func (signature *Signature) VerifyHashWithPublicKey(publicKey *PublicKey, messageHash []byte) bool {
	nativePublicKey, err := publicKey.ToNative()
	if err != nil {
		return false
	}

	nativeR, nativeS := signature.ToNative()
	return nativeEcdsa.Verify(nativePublicKey, messageHash, nativeR, nativeS)
}

func (signature *Signature) VerifyHashWithRecoveryId(recoveryId *RecoveryId, messageHash []byte) bool {
	recoveredPublicKey, err := signature.RecoverPublicKey(recoveryId, messageHash)
	if err != nil {
		return false
	}

	return signature.VerifyHashWithPublicKey(recoveredPublicKey, messageHash)
}

// RecoverPublicKey recovers PublicKey (point on the curve) based od messageHash, public key and recovery id.
func (signature *Signature) RecoverPublicKey(recoveryId *RecoveryId, messageHash []byte) (*PublicKey, error) {
	if recoveryId == nil {
		return nil, errs.NewIsNil("no recovery id")
	}

	curve, err := curves.GetCurveByName(signature.R.Point().CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not find curve (%s) of the R point", signature.R.Point().CurveName())
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
	if (recoveryId.V & 2) != 0 {
		rx = new(big.Int).Add(rx, subGroupOrder)
	}
	rxBytes := rx.Bytes()
	if len(rxBytes) < 32 {
		rxBytes = append(make([]byte, 32-len(rxBytes)), rxBytes...)
	}
	ryCompressed := []byte{byte(2)}
	if (recoveryId.V & 1) != 0 {
		ryCompressed[0]++
	}
	affine := append(ryCompressed[:], rxBytes...)
	bigR, err := signature.R.Point().FromAffineCompressed(affine[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate R")
	}

	// Calculate point Q (public key)
	//  Q = r^(-1)(sR - zG)
	zInt, err := hashToInt(messageHash, curve)
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
	bigQ := (bigR.Mul(signature.S).Sub(curve.ScalarBaseMult(z))).Mul(rInv)

	return &PublicKey{Q: bigQ}, nil
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

func (signature *Signature) ToNative() (r *big.Int, s *big.Int) {
	return signature.R.BigInt(), signature.S.BigInt()
}

func (signature *Signature) FromNative(curve elliptic.Curve, r *big.Int, s *big.Int) (*Signature, error) {
	knoxCurve, err := curves.GetCurveByName(curve.Params().Name)
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "curve not supported")
	}

	knoxR, err := knoxCurve.NewScalar().SetBigInt(r)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate r")
	}
	knoxS, err := knoxCurve.NewScalar().SetBigInt(s)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate s")
	}

	signature.R = knoxR
	signature.S = knoxS
	return signature, nil
}

func (pk *PublicKey) ToNative() (nativePublicKey *nativeEcdsa.PublicKey, err error) {
	curve, err := curves.GetCurveByName(pk.Q.CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not find curve of the public key")
	}
	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
	}

	pkX, pkY := getPointCoordinates(pk.Q)
	return &nativeEcdsa.PublicKey{
		Curve: nativeCurve,
		X:     pkX,
		Y:     pkY,
	}, nil
}

func (pk *PublicKey) FromNative(nativePublicKey *nativeEcdsa.PublicKey) (*PublicKey, error) {
	curve, err := curves.GetCurveByName(nativePublicKey.Curve.Params().Name)
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not find curve of the public key")
	}

	q, err := curve.NewIdentityPoint().Set(nativePublicKey.X, nativePublicKey.Y)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set point coordinates")
	}

	return &PublicKey{
		Q: q,
	}, nil
}

func (sk *SecretKey) ToNative() (nativePrivateKey *nativeEcdsa.PrivateKey, err error) {
	nativePublicKey, err := sk.PublicKey.ToNative()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot map public key")
	}

	return &nativeEcdsa.PrivateKey{
		PublicKey: *nativePublicKey,
		D:         sk.D.BigInt(),
	}, nil
}

func (sk *SecretKey) FromNative(nativePrivateKey *nativeEcdsa.PrivateKey) (secretKey *SecretKey, err error) {
	publicKey, err := new(PublicKey).FromNative(&nativePrivateKey.PublicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot map public key")
	}

	curve, err := curves.GetCurveByName(nativePrivateKey.Curve.Params().Name)
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not find curve of the private key")
	}
	d, err := curve.NewScalar().SetBigInt(nativePrivateKey.D)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set scalar")
	}

	return &SecretKey{
		PublicKey: *publicKey,
		D:         d,
	}, nil
}

func hashToInt(hash []byte, curve *curves.Curve) (*big.Int, error) {
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
