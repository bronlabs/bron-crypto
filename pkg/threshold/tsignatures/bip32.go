package tsignatures

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func PublicChildKeyDerivation(publicKey curves.Point, chainCode [32]byte, i uint32) (curves.Scalar, [32]byte, error) {
	if i >= (1 << 31) {
		return nil, [32]byte{}, errs.NewFailed("unsupported derivation")
	}

	hmacSha512 := hmac.New(sha512.New, chainCode[:])
	hmacSha512.Write(publicKey.ToAffineCompressed())
	hmacSha512.Write(binary.BigEndian.AppendUint32(nil, i))
	digest := hmacSha512.Sum(nil)

	curve := publicKey.Curve()
	shift, err := curve.ScalarField().Element().SetBytes(digest[:32])
	if err != nil {
		return nil, [32]byte{}, errs.WrapFailed(err, "cannot create scalar from bytes")
	}
	// make sure it wasn't reduced
	if !bytes.Equal(digest[:32], shift.Bytes()) {
		return nil, [32]byte{}, errs.NewFailed("invalid derivation")
	}

	var childChainCode [32]byte
	copy(childChainCode[:], digest[32:])

	return shift, childChainCode, nil
}
