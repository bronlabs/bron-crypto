package signatures

import (
	"crypto/sha512"
	"encoding/binary"
	"io"
	"slices"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
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

// DeriveChildKeys derives a non-hardened child key shift and chain code from a parent
// public key and chain code at index i. Hardened indices (i >= 2^31) are rejected since
// hardened derivation requires the private key.
//
// The construction used depends on the curve of publicKey:
//
//   - secp256k1 (k256): standards-compliant BIP32 per bitcoin.org/bip-0032, using
//     HMAC-SHA512 over (compressed pk || ser32(i)) keyed by the chain code. Returns
//     ErrInvalidDerivation when IL == 0 or IL >= n, as required by BIP32 §5. Interops
//     with wallets that follow BIP32.
//
//   - any other curve: a non-standard BIP32-like construction (see bip32Like) that uses a
//     blake2b XOF keyed by the chain code over (pk.Bytes() || ser32(i)), produces a
//     wide-reduced scalar shift, and rejects only IL == 0. This path does NOT implement
//     BIP32 and is NOT interoperable with any external derivation spec. It is dispatched
//     purely on curve Name() inequality with k256, so callers MUST NOT assume BIP32
//     compatibility for ed25519, ristretto, BLS, or any other curve — nor that derivations
//     remain stable across curves with the same name as k256 but a different underlying type.
//
// Callers who need BIP32 semantics on non-k256 curves should use a dedicated derivation
// scheme (e.g. SLIP-0010 for ed25519) instead of this function.
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
	// BIP32 §5: the derivation fails if IL == 0 or IL ≥ n; the round-trip byte compare
	// detects the ≥ n case, IsZero covers the all-zero case.
	_, isEq, _ := ct.CompareBytes(digest[:32], shift.Bytes())
	if isEq != ct.True || shift.IsZero() {
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
	if shift.IsZero() {
		return *new(SH), nil, ErrInvalidDerivation.WithStackFrame()
	}

	return shift, childChainCode, nil
}
