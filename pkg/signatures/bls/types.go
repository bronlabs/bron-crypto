package bls

import (
	"crypto/subtle"
	"encoding"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381"
	bimpl "github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

const (
	// Public key size in G1.
	PublicKeySizeInG1 = 48
	// Signature size in G2.
	SignatureSizeInG2 = 96
	// Proof of Possession in G2.
	ProofOfPossessionSizeInG2 = 96

	// Public key size in G2.
	PublicKeySizeInG2 = 96
	// Signature size in G1.
	SignatureSizeInG1 = 48
	// Proof of Possession in G1.
	ProofOfPossessionSizeInG1 = 48
)

type (
	G1 = *bls12381.PointG1
	G2 = *bls12381.PointG2
)

type KeySubGroup interface {
	curves.PairingPoint
	G1 | G2
}

var (
	_ encoding.BinaryMarshaler   = (*PrivateKey[*bls12381.PointG1])(nil)
	_ encoding.BinaryUnmarshaler = (*PrivateKey[*bls12381.PointG1])(nil)
)

type PrivateKey[K KeySubGroup] struct {
	d         *bls12381.ScalarBls12381
	PublicKey *PublicKey[K]

	_ helper_types.Incomparable
}

func (sk *PrivateKey[K]) D() curves.PairingScalar {
	return sk.d
}

func (sk *PrivateKey[K]) Validate() error {
	if sk.d == nil {
		return errs.NewIsNil("scalar is nil")
	}
	if sk.d.IsZero() {
		return errs.NewIsZero("secret key cannot be zero")
	}
	if err := sk.PublicKey.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "public key validation failed")
	}
	return nil
}

// Serialise a secret key to raw bytes.
func (sk *PrivateKey[K]) MarshalBinary() ([]byte, error) {
	bytes := sk.d.Bytes()
	return bitstring.ReverseBytes(bytes), nil
}

// Deserialize a secret key from raw bytes
// Cannot be zero. Must be 32 bytes and cannot be all zeroes.
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03#section-2.3
func (sk *PrivateKey[K]) UnmarshalBinary(data []byte) error {
	if len(data) != SecretKeySize {
		return errs.NewInvalidLength("secret key must be %d bytes", SecretKeySize)
	}
	zeros := make([]byte, len(data))
	if subtle.ConstantTimeCompare(data, zeros) == 1 {
		return errs.NewIsZero("secret key cannot be zero")
	}
	var bb [impl.FieldBytes]byte
	copy(bb[:], bitstring.ReverseBytes(data))
	value, err := bimpl.FqNew().SetBytes(&bb)
	if err != nil {
		return errs.WrapSerializationError(err, "couldn't set bytes")
	}
	point := new(K)
	sk.d = &bls12381.ScalarBls12381{
		Value:  value,
		Point_: *point,
	}
	return nil
}

var (
	_ encoding.BinaryMarshaler   = (*PublicKey[*bls12381.PointG1])(nil)
	_ encoding.BinaryUnmarshaler = (*PublicKey[*bls12381.PointG1])(nil)
)

type PublicKey[K KeySubGroup] struct {
	Y curves.PairingPoint

	_ helper_types.Incomparable
}

// The Validate algorithm ensures that a public key is valid. In particular, it ensures that a public key represents a valid, non-identity point that is in the correct subgroup.
// Note that if the RogueKeyPreventionScheme is POP, this public key must be accompanied with a proof of possession.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-keyvalidate
func (pk *PublicKey[K]) Validate() error {
	if pk.Y == nil {
		return errs.NewIsNil("public key value is nil")
	}
	if pk.Y.IsIdentity() {
		return errs.NewIsIdentity("public key value is identity")
	}
	// TODO: why this works then?
	if pk.Y.ClearCofactor().IsIdentity() {
		return errs.NewIsIdentity("public key value is identity after clearing cofactor")
	}
	if !pk.Y.IsTorsionFree() {
		return errs.NewVerificationFailed("public key is not torsion free")
	}
	return nil
}

func (pk *PublicKey[K]) Size() int {
	if pk.inG1() {
		return PublicKeySizeInG1
	}
	return PublicKeySizeInG2
}

// Serialise a public key to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (pk PublicKey[K]) MarshalBinary() ([]byte, error) {
	out := pk.Y.ToAffineCompressed()
	return out, nil
}

// Deserialize a public key from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the public key
// otherwise it will return an error.
func (pk *PublicKey[K]) UnmarshalBinary(data []byte) error {
	size := pk.Size()
	if len(data) != size {
		return errs.NewInvalidLength("public key must be %d bytes", size)
	}
	// var blob [PublicKeySize]byte
	blob := make([]byte, size)
	copy(blob, data)
	t := new(K)
	p, err := (*t).FromAffineCompressed(blob)
	if err != nil {
		return errs.WrapSerializationError(err, "couldn't deserialize data in a point of G1")
	}
	if p.IsIdentity() {
		return errs.NewIsZero("public keys cannot be zero")
	}
	var ok bool
	pk.Y, ok = p.(curves.PairingPoint)
	if !ok {
		return errs.NewSerializationError("point is not a pairing type")
	}
	return nil
}

func (pk *PublicKey[K]) inG1() bool {
	return pk.Y.CurveName() == bls12381.G1Name
}

type SignatureSubGroup = KeySubGroup

var (
	_ encoding.BinaryMarshaler   = (*Signature[*bls12381.PointG2])(nil)
	_ encoding.BinaryUnmarshaler = (*Signature[*bls12381.PointG2])(nil)
)

type Signature[S SignatureSubGroup] struct {
	Value curves.PairingPoint

	_ helper_types.Incomparable
}

func (sig *Signature[S]) Size() int {
	if sig.inG1() {
		return PublicKeySizeInG1
	}
	return PublicKeySizeInG2
}

// Serialise a signature to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (sig *Signature[S]) MarshalBinary() ([]byte, error) {
	out := sig.Value.ToAffineCompressed()
	return out, nil
}

// Deserialize a signature from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the Signature
// otherwise it will return an error.
func (sig *Signature[S]) UnmarshalBinary(data []byte) error {
	size := sig.Size()
	if len(data) != size {
		return errs.NewInvalidLength("signature must be %d bytes", size)
	}
	blob := make([]byte, size)
	copy(blob, data)
	t := new(S)
	p, err := (*t).FromAffineCompressed(blob)
	if err != nil {
		return errs.WrapSerializationError(err, "couldn't deserialize data in a point of G1")
	}
	if p.IsIdentity() {
		return errs.NewIsZero("public keys cannot be zero")
	}

	var ok bool
	sig.Value, ok = p.(curves.PairingPoint)
	if !ok {
		return errs.NewSerializationError("point is not a pairing type")
	}
	return nil
}

func (sig *Signature[S]) inG1() bool {
	return sig.Value.CurveName() == bls12381.G1Name
}

// type aliasing of generic types is not supported. So, sitll have to copy identical stuff.
var (
	_ encoding.BinaryMarshaler   = (*Signature[*bls12381.PointG2])(nil)
	_ encoding.BinaryUnmarshaler = (*Signature[*bls12381.PointG2])(nil)
)

type ProofOfPossession[S SignatureSubGroup] struct {
	Value curves.PairingPoint

	_ helper_types.Incomparable
}

func (pop *ProofOfPossession[S]) Size() int {
	if pop.inG1() {
		return PublicKeySizeInG1
	}
	return PublicKeySizeInG2
}

// Serialise a signature to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (pop *ProofOfPossession[S]) MarshalBinary() ([]byte, error) {
	out := pop.Value.ToAffineCompressed()
	return out, nil
}

// Deserialize a signature from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the Signature
// otherwise it will return an error.
func (pop *ProofOfPossession[S]) UnmarshalBinary(data []byte) error {
	size := pop.Size()
	if len(data) != size {
		return errs.NewInvalidLength("signature must be %d bytes", size)
	}
	blob := make([]byte, size)
	copy(blob, data)
	t := new(S)
	p, err := (*t).FromAffineCompressed(blob)
	if err != nil {
		return errs.WrapSerializationError(err, "couldn't deserialize data in a point of G1")
	}
	if p.IsIdentity() {
		return errs.NewIsZero("public keys cannot be zero")
	}

	var ok bool
	pop.Value, ok = p.(curves.PairingPoint)
	if !ok {
		return errs.NewSerializationError("point is not a pairing type")
	}
	return nil
}

func (pop *ProofOfPossession[S]) inG1() bool {
	return pop.Value.CurveName() == bls12381.G1Name
}
