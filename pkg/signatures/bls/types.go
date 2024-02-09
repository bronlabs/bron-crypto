package bls

import (
	"crypto/subtle"
	"encoding"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	bimpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
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

type KeySubGroup = bls12381.SourceSubGroups

var (
	_ encoding.BinaryMarshaler   = (*PrivateKey[bls12381.G1])(nil)
	_ encoding.BinaryUnmarshaler = (*PrivateKey[bls12381.G1])(nil)

	_ encoding.BinaryMarshaler   = (*PrivateKey[bls12381.G2])(nil)
	_ encoding.BinaryUnmarshaler = (*PrivateKey[bls12381.G2])(nil)
)

type PrivateKey[K KeySubGroup] struct {
	d         *bls12381.Scalar
	PublicKey *PublicKey[K]

	_ types.Incomparable
}

func NewPrivateKey[K KeySubGroup](d curves.Scalar) (*PrivateKey[K], error) {
	sk, ok := d.(*bls12381.Scalar)
	if !ok {
		return nil, errs.NewInvalidType("scalar is not for the right subgroup")
	}
	sk.G = bls12381.GetSourceSubGroup[K]()
	if bls12381.GetSourceSubGroup[K]().Name() != d.ScalarField().Curve().Name() {
		return nil, errs.NewInvalidCurve(
			"Key subgroup (%s) and d's subgroup (%s) are not the same",
			bls12381.GetSourceSubGroup[K]().Name(),
			d.ScalarField().Curve().Name(),
		)
	}
	Y := d.ScalarField().Curve().ScalarBaseMult(sk).(curves.PairingPoint)
	return &PrivateKey[K]{
		d: sk,
		PublicKey: &PublicKey[K]{
			Y: Y,
		},
	}, nil
}

func (sk *PrivateKey[K]) D() curves.Scalar {
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
	return utils.SliceReverse(bytes), nil
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
	var bb [base.FieldBytes]byte
	copy(bb[:], utils.SliceReverse(data))
	value, err := bimpl.FqNew().SetBytes(&bb)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't set bytes")
	}
	sk.d = &bls12381.Scalar{
		V: value,
		G: bls12381.GetSourceSubGroup[K](),
	}
	Y := sk.d.ScalarField().Curve().ScalarBaseMult(sk.d).(curves.PairingPoint)
	sk.PublicKey = &PublicKey[K]{
		Y: Y,
	}

	return nil
}

var (
	_ encoding.BinaryMarshaler   = (*PublicKey[bls12381.G1])(nil)
	_ encoding.BinaryUnmarshaler = (*PublicKey[bls12381.G1])(nil)

	_ encoding.BinaryMarshaler   = (*PublicKey[bls12381.G2])(nil)
	_ encoding.BinaryUnmarshaler = (*PublicKey[bls12381.G2])(nil)
)

type PublicKey[K KeySubGroup] struct {
	Y curves.PairingPoint

	_ types.Incomparable
}

// The Validate algorithm ensures that a public key is valid. In particular, it ensures that a public key represents a valid, non-identity point that is in the correct subgroup.
// Note that if the RogueKeyPreventionScheme is POP, this public key must be accompanied with a proof of possession.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-keyvalidate
func (pk *PublicKey[K]) Validate() error {
	subGroup := bls12381.GetSourceSubGroup[K]()
	if pk == nil {
		return errs.NewIsNil("public key is nil")
	}
	if pk.Y == nil {
		return errs.NewIsNil("public key value is nil")
	}
	if pk.Y.IsIdentity() {
		return errs.NewIsIdentity("public key value is identity")
	}
	if pk.Y.IsSmallOrder() {
		return errs.NewIsIdentity("public key value is small order")
	}
	if !pk.Y.IsTorsionElement(subGroup.SubGroupOrder()) {
		return errs.NewVerificationFailed("public key is not torsion free")
	}
	return nil
}

func (pk *PublicKey[K]) Size() int {
	if pk.InG1() {
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
	blob := make([]byte, size)
	copy(blob, data)
	g := bls12381.GetSourceSubGroup[K]()
	p, err := g.Element().FromAffineCompressed(blob)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't deserialize data in a point of G1")
	}
	if p.IsIdentity() {
		return errs.NewIsZero("public keys cannot be zero")
	}
	pk.Y = p.(curves.PairingPoint)
	return nil
}

func (*PublicKey[K]) InG1() bool {
	return bls12381.GetSourceSubGroup[K]().Name() == bls12381.NewG1().Name()
}

type SignatureSubGroup = KeySubGroup

var (
	_ encoding.BinaryMarshaler   = (*Signature[bls12381.G2])(nil)
	_ encoding.BinaryUnmarshaler = (*Signature[bls12381.G2])(nil)

	_ encoding.BinaryMarshaler   = (*Signature[bls12381.G1])(nil)
	_ encoding.BinaryUnmarshaler = (*Signature[bls12381.G1])(nil)
)

type Signature[S SignatureSubGroup] struct {
	Value curves.PairingPoint

	_ types.Incomparable
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
	g := bls12381.GetSourceSubGroup[S]()
	p, err := g.Element().FromAffineCompressed(blob)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't deserialize data in a point of G1")
	}
	if p.IsIdentity() {
		return errs.NewIsZero("signatures cannot be zero")
	}

	sig.Value = p.(curves.PairingPoint)
	return nil
}

func (*Signature[S]) inG1() bool {
	return bls12381.GetSourceSubGroup[S]().Name() == bls12381.NewG1().Name()
}

// type aliasing of generic types is not supported. So, sitll have to copy identical stuff.
var (
	_ encoding.BinaryMarshaler   = (*Signature[bls12381.G2])(nil)
	_ encoding.BinaryUnmarshaler = (*Signature[bls12381.G2])(nil)

	_ encoding.BinaryMarshaler   = (*Signature[bls12381.G1])(nil)
	_ encoding.BinaryUnmarshaler = (*Signature[bls12381.G1])(nil)
)

type ProofOfPossession[S SignatureSubGroup] struct {
	Value curves.PairingPoint

	_ types.Incomparable
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
	g := bls12381.GetSourceSubGroup[S]()
	p, err := g.Element().FromAffineCompressed(blob)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't deserialize data in a point of G1")
	}
	if p.IsIdentity() {
		return errs.NewIsZero("public keys cannot be zero")
	}

	pop.Value = p.(curves.PairingPoint)
	return nil
}

func (*ProofOfPossession[S]) inG1() bool {
	return bls12381.GetSourceSubGroup[S]().Name() == bls12381.NewG1().Name()
}
