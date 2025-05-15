package tsignatures

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func ChildKeyDerivation(publicKey curves.Point, chainCode []byte, i uint32) (curves.Scalar, []byte, error) {
	if i >= (1 << 31) {
		return nil, nil, errs.NewFailed("unsupported derivation")
	}
	if publicKey.Curve().Name() == k256.NewCurve().Name() {
		return bip32ChildKeyDerivation(publicKey.(*k256.Point), chainCode, i) //nolint:errcheck // never throw error
	} else {
		return genericChildKeyDerivation(publicKey, chainCode, i)
	}
}

func bip32ChildKeyDerivation(publicKey *k256.Point, chainCode []byte, i uint32) (*k256.Scalar, []byte, error) {
	hmacSha512 := hmac.New(sha512.New, chainCode)
	hmacSha512.Write(publicKey.ToAffineCompressed())
	hmacSha512.Write(binary.BigEndian.AppendUint32(nil, i))
	digest := hmacSha512.Sum(nil)

	childChainCode := digest[32:]
	shift, err := k256.NewCurve().ScalarField().Element().SetBytes(digest[:32])
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create scalar from bytes")
	}
	// make sure it wasn't reduced
	if !bytes.Equal(digest[:32], shift.Bytes()) {
		return nil, nil, errs.NewFailed("invalid derivation")
	}

	//nolint:errcheck // never throws error
	return shift.(*k256.Scalar), childChainCode, nil
}

func genericChildKeyDerivation(publicKey curves.Point, chainCode []byte, i uint32) (curves.Scalar, []byte, error) {
	scalarWideLen := publicKey.Curve().ScalarField().WideElementSize()
	digestLen := scalarWideLen + 32

	xof, err := blake2b.NewXOF(uint32(digestLen), chainCode)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create blake2b xof")
	}

	_, err = xof.Write(publicKey.ToAffineCompressed())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot hash public key")
	}
	_, err = xof.Write(binary.BigEndian.AppendUint32(nil, i))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot write index")
	}
	digest := make([]byte, digestLen)
	_, err = io.ReadFull(xof, digest)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot read digest")
	}

	childChainCode := digest[scalarWideLen:]
	shift, err := publicKey.Curve().ScalarField().Element().SetBytesWide(digest[:scalarWideLen])
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create scalar from bytes")
	}

	return shift, childChainCode, nil
}
