package signatures

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"io"
	"slices"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/errs-go/pkg/errs"
)

type AdditivelyDerivablePublicKey[
	PK interface {
		PublicKey[PK]
		base.Transparent[PKV]
	}, PKV interface {
		algebra.AbelianGroupElement[PKV, SH]
		algebra.AdditiveGroupElement[PKV]
	}, SH algebra.PrimeFieldElement[SH],
] interface {
	PublicKey[PK]
	base.Transparent[PKV]
}

func DeriveChildKeys[
	PK AdditivelyDerivablePublicKey[PK, PKV, SH],
	PKV interface {
		algebra.AbelianGroupElement[PKV, SH]
		algebra.AdditiveGroupElement[PKV]
	}, SH algebra.PrimeFieldElement[SH],
](publicKey PK, chainCode []byte, i uint32) (shift SH, childChainCode []byte, err error) {
	if utils.IsNil(publicKey) {
		return *new(SH), nil, ErrInvalidArgument.WithMessage("public key is nil")
	}
	if i >= (1 << 31) {
		return *new(SH), nil, ErrInvalidDerivation.WithStackFrame()
	}
	if publicKey.Value().Structure().Name() == k256.NewCurve().Name() {
		shift, childChainCode, err := bip32(any(publicKey.Value()).(*k256.Point), chainCode, i) //nolint:errcheck // false positive
		if err != nil {
			return *new(SH), nil, errs.Wrap(err).WithMessage("cannot derive child key")
		}
		return any(shift).(SH), childChainCode, nil //nolint:errcheck // false positive
	} else {
		return bip32Like(publicKey, chainCode, i)
	}
}

func bip32(publicKey *k256.Point, chainCode []byte, i uint32) (*k256.Scalar, []byte, error) {
	digest, err := hashing.Hmac(chainCode, sha512.New, publicKey.ToCompressed(), binary.BigEndian.AppendUint32(nil, i))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot hash public key")
	}

	childChainCode := digest[32:]
	sf := k256.NewScalarField()
	shift, err := sf.FromBytes(digest[:32])
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create scalar from bytes")
	}
	// make sure it wasn't reduced
	if !bytes.Equal(digest[:32], shift.Bytes()) {
		return nil, nil, ErrInvalidDerivation.WithStackFrame()
	}
	return shift, childChainCode, nil
}

func bip32Like[
	PK AdditivelyDerivablePublicKey[PK, PKV, SH],
	PKV interface {
		algebra.AbelianGroupElement[PKV, SH]
		algebra.AdditiveGroupElement[PKV]
	}, SH algebra.PrimeFieldElement[SH],
](publicKey PK, chainCode []byte, i uint32) (shift SH, childChainCode []byte, err error) {
	pkSpace, ok := publicKey.Value().Structure().(algebra.AbelianGroup[PKV, SH])
	if !ok {
		return *new(SH), nil, ErrInvalidArgument.WithMessage("public key does not implement FiniteAbelianGroup")
	}
	sf, ok := pkSpace.ScalarStructure().(algebra.PrimeField[SH])
	if !ok {
		return *new(SH), nil, ErrInvalidArgument.WithMessage("public key does not implement PrimeField")
	}
	scalarWideLen := sf.WideElementSize()
	digestLen := scalarWideLen + 32

	xof, err := blake2b.NewXOF(uint32(digestLen), chainCode)
	if err != nil {
		return *new(SH), nil, errs.Wrap(err).WithMessage("cannot create blake2b xof")
	}

	if _, err := xof.Write(slices.Concat(publicKey.Value().Bytes(), binary.BigEndian.AppendUint32(nil, i))); err != nil {
		return *new(SH), nil, errs.Wrap(err).WithMessage("cannot hash public key")
	}
	digest := make([]byte, digestLen)
	if _, err := io.ReadFull(xof, digest); err != nil {
		return *new(SH), nil, errs.Wrap(err).WithMessage("cannot read digest")
	}

	childChainCode = digest[scalarWideLen:]
	shift, err = sf.FromWideBytes(digest[:scalarWideLen])
	if err != nil {
		return *new(SH), nil, errs.Wrap(err).WithMessage("cannot create scalar from bytes")
	}

	return shift, childChainCode, nil
}

var (
	ErrInvalidDerivation = errs.New("invalid derivation")
	ErrInvalidArgument   = errs.New("invalid argument")
)
