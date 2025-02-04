package tsignatures

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
)

func DeriveBip32(extShare *ExtendedSigningKeyShare, derivationPath []uint32) *ExtendedSigningKeyShare {
	pk := extShare.PublicKey
	share := extShare.Share
	code := extShare.ChainCode
	for _, i := range derivationPath {
		pk, share, code = ckd(pk, share, code, i)
	}

	return &ExtendedSigningKeyShare{
		SigningKeyShare: SigningKeyShare{
			Share:     share,
			PublicKey: pk,
		},
		ChainCode: code,
	}
}

func ckd(parentPublicKey curves.Point, parentShare curves.Scalar, parentChainCode ChainCode, i uint32) (childPublicKey curves.Point, childShare curves.Scalar, childChainCode ChainCode) {
	if i >= (1 << 31) {
		panic("unsupported derivation")
	}

	hmacSha512 := hmac.New(sha512.New, parentChainCode[:])
	hmacSha512.Write(parentPublicKey.ToAffineCompressed())
	hmacSha512.Write(binary.BigEndian.AppendUint32(nil, i))
	digest := hmacSha512.Sum(nil)

	curve := parentPublicKey.Curve()
	shift, err := curve.ScalarField().Element().SetBytes(digest[:32])
	if err != nil {
		panic("error")
	}
	// make sure it wasn't reduced
	if !bytes.Equal(digest[:32], shift.Bytes()) {
		panic("invalid derivation")
	}

	childShare = parentShare.Add(shift)
	childPublicKey = parentPublicKey.Add(curve.ScalarBaseMult(shift))
	if childPublicKey.IsAdditiveIdentity() {
		panic("invalid")
	}

	copy(childChainCode[:], digest[32:])
	return childPublicKey, childShare, childChainCode
}
