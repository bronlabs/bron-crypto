package hashing

import (
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

type MappingMethod uint

const (
	// SameAsHashSize indicates that the `Scalar.SetBytes()` method is used if
	// the hash size is equal to FieldBytes (e.g., sha256, sha3), and
	// `Scalar.SetBytesWide()` if the hash size is equal to WideFieldBytes (e.g., sha512).
	SameAsHashSize MappingMethod = iota
	// AlwaysUseWideBytes indicates that the `Scalar.SetBytesWide()` method is used
	// regardless of the hash size.
	AlwaysUseWideBytes
)

type FiatShamir struct {
	hashingMethod func(h func() hash.Hash, xs ...[]byte) ([]byte, error)
	mappingMethod MappingMethod
}

// NewFiatShamir returns a FiatShamir instance that uses the provided hashing method.
func NewFiatShamir(hashingMethod func(h func() hash.Hash, xs ...[]byte) ([]byte, error), mappingMethod MappingMethod) *FiatShamir {
	return &FiatShamir{
		hashingMethod: hashingMethod,
		mappingMethod: mappingMethod,
	}
}

// NewSchnorrCompatibleFiatShamir returns a FiatShamir instance compatible with Schnorr signing scheme.
func NewSchnorrCompatibleFiatShamir() *FiatShamir {
	return &FiatShamir{
		hashingMethod: Hash,
		mappingMethod: SameAsHashSize,
	}
}

// GenerateChallenge computes a challenge scalar writing all inputs to the hash
// and maps its digest to a curve scalar according to the digest size. It does
// not care about potential biases in the resulting scalar, as it is used for
// Schnorr signatures.
func (fs *FiatShamir) GenerateChallenge(cipherSuite *integration.CipherSuite, xs ...[]byte) (challenge curves.Scalar, err error) {
	for _, x := range xs {
		if x == nil {
			return nil, errs.NewIsNil("an input is nil")
		}
	}

	digest, err := fs.hashingMethod(cipherSuite.Hash, xs...)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not compute fiat shamir hash")
	}

	switch fs.mappingMethod {
	case SameAsHashSize:
		switch L := len(digest); {
		case L == base.FieldBytes:
			challenge, err = cipherSuite.Curve.Scalar().SetBytes(digest)
		case L == base.WideFieldBytes:
			challenge, err = cipherSuite.Curve.Scalar().SetBytesWide(digest)
		default:
			return nil, errs.WrapSerialisation(err, "digest length %d is not supported", len(digest))
		}
	case AlwaysUseWideBytes:
		challenge, err = cipherSuite.Curve.Scalar().SetBytesWide(digest)
	default:
		return nil, errs.NewInvalidArgument("Unknown mapping method")
	}
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not compute fiat shamir challenge")
	}
	return challenge, nil
}
