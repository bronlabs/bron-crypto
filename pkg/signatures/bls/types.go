package bls

import (
	"encoding"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

const (
	PublicKeySizeInG1         = 48
	SignatureSizeInG2         = 96
	ProofOfPossessionSizeInG2 = 96

	PublicKeySizeInG2         = 96
	SignatureSizeInG1         = 48
	ProofOfPossessionSizeInG1 = 48
)

var (
	_ encoding.BinaryMarshaler   = (*PrivateKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.Scalar])(nil)
	_ encoding.BinaryUnmarshaler = (*PrivateKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.Scalar])(nil)

	_ encoding.BinaryMarshaler   = (*PrivateKey[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.Scalar])(nil)
	_ encoding.BinaryUnmarshaler = (*PrivateKey[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.Scalar])(nil)
)

type PrivateKey[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] struct {
	d         S
	PublicKey *PublicKey[P, B, S]

	_ ds.Incomparable
}

func NewPrivateKey[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]](curve curves.Curve[P, B, S], sk S) (*PrivateKey[P, B, S], error) {
	Y := curve.Generator().ScalarMul(sk)
	return &PrivateKey[P, B, S]{
		d: sk,
		PublicKey: &PublicKey[P, B, S]{
			Y: Y,
		},
	}, nil
}

func (sk *PrivateKey[P, B, S]) D() S {
	return sk.d
}

func (sk *PrivateKey[P, B, S]) Validate() error {
	if sk == nil {
		return errs.NewIsNil("receiver")
	}
	// TODO(aalireza): nil check somehow?
	//if sk.d == nil {
	//	return errs.NewIsNil("scalar is nil")
	//}
	if sk.d.IsZero() {
		return errs.NewIsZero("secret key cannot be zero")
	}
	if err := sk.PublicKey.Validate(); err != nil {
		return errs.WrapValidation(err, "public key validation failed")
	}
	return nil
}

// MarshalBinary serialises a secret key to raw bytes.
func (sk *PrivateKey[P, B, S]) MarshalBinary() ([]byte, error) {
	bytes := sk.d.Bytes()
	return sliceutils.Reverse(bytes), nil
}

// UnmarshalBinary deserializes a secret key from raw bytes
// Cannot be zero. Must be 32 bytes and cannot be all zeroes.
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03#section-2.3
func (sk *PrivateKey[P, B, S]) UnmarshalBinary(data []byte) error {
	// TODO(aalireza): how to compute public key if it's not serialized and no access to curve
	// TODO(aalireza): my two cents - we should not use Marshal/Unmarshal to match the format, marshal/unmarshal is, well... for marshalling only
	curve, err := curves.GetCurve(sk.PublicKey.Y) // this is GetCurve(nil) - it works but it's sketchy to say the least
	if err != nil {
		return err
	}

	sk.d, err = curve.ScalarField().FromBytes(sliceutils.Reversed(data))
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't set bytes")
	}

	Y := curve.Generator().ScalarMul(sk.d)
	sk.PublicKey = &PublicKey[P, B, S]{
		Y: Y,
	}

	return nil
}

var (
	_ encoding.BinaryMarshaler   = (*PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.Scalar])(nil)
	_ encoding.BinaryUnmarshaler = (*PublicKey[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.Scalar])(nil)

	_ encoding.BinaryMarshaler   = (*PublicKey[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.Scalar])(nil)
	_ encoding.BinaryUnmarshaler = (*PublicKey[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.Scalar])(nil)
)

type PublicKey[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] struct {
	Y P

	_ ds.Incomparable
}

func (pk *PublicKey[P, B, S]) Equal(other *PublicKey[P, B, S]) bool {
	if other == nil {
		return pk == other
	}

	return pk.Y.Equal(other.Y)
}

// The Validate algorithm ensures that a public key is valid. In particular, it ensures that a public key represents a valid, non-identity point that is in the correct subgroup.
// Note that if the RogueKeyPreventionScheme is POP, this public key must be accompanied by a proof of possession.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-keyvalidate
func (pk *PublicKey[P, B, S]) Validate() error {
	if pk == nil {
		return errs.NewIsNil("public key is nil")
	}
	// TODO(aalireza): nil check somehow?
	//if pk.Y == nil {
	//	return errs.NewIsNil("public key value is nil")
	//}
	if !pk.Y.IsTorsionFree() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	if pk.Y.IsOpIdentity() {
		return errs.NewIsIdentity("public key value is identity")
	}
	return nil
}

func (pk *PublicKey[P, B, S]) Size() int {
	curve, err := curves.GetCurve(pk.Y)
	if err != nil {
		panic(err)
	}
	return curve.BaseField().ElementSize()
}

// MarshalBinary Serialises a public key to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (pk *PublicKey[P, B, S]) MarshalBinary() ([]byte, error) {
	out := pk.Y.ToAffineCompressed()
	return out, nil
}

// UnmarshalBinary Deserializes a public key from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the public key
// otherwise it will return an error.
func (pk *PublicKey[P, B, S]) UnmarshalBinary(data []byte) error {
	// TODO(aalireza): not strictly correct, as pk.Y is not initialized (nil)
	curve, err := curves.GetCurve(pk.Y)
	if err != nil {
		return err
	}

	p, err := curve.FromAffineCompressed(data)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't deserialize data in a point of G1")
	}
	if p.IsOpIdentity() {
		return errs.NewIsZero("public keys cannot be zero")
	}
	pk.Y = p
	return nil
}

var (
	_ encoding.BinaryMarshaler   = (*Signature[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.Scalar])(nil)
	_ encoding.BinaryUnmarshaler = (*Signature[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.Scalar])(nil)

	_ encoding.BinaryMarshaler   = (*Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.Scalar])(nil)
	_ encoding.BinaryUnmarshaler = (*Signature[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.Scalar])(nil)
)

type Signature[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] struct {
	Value P

	_ ds.Incomparable
}

func (sig *Signature[P, B, S]) Size() int {
	curve, err := curves.GetCurve(sig.Value)
	if err != nil {
		panic(err)
	}
	baseField := curve.BaseField()
	return baseField.ElementSize()
}

// MarshalBinary Serialises a signature to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (sig *Signature[P, B, S]) MarshalBinary() ([]byte, error) {
	out := sig.Value.ToAffineCompressed()
	return out, nil
}

// UnmarshalBinary Deserializes a signature from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the Signature
// otherwise it will return an error.
func (sig *Signature[P, B, S]) UnmarshalBinary(data []byte) error {
	curve, err := curves.GetCurve(sig.Value)
	p, err := curve.FromAffineCompressed(data)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't deserialize data in a point of G1")
	}
	if p.IsOpIdentity() {
		return errs.NewIsZero("signatures cannot be zero")
	}

	sig.Value = p
	return nil
}

//
//// type aliasing of generic types is not supported. So, sitll have to copy identical stuff.
//var (
//	_ encoding.BinaryMarshaler   = (*Signature[bls12381.G2])(nil)
//	_ encoding.BinaryUnmarshaler = (*Signature[bls12381.G2])(nil)
//
//	_ encoding.BinaryMarshaler   = (*Signature[bls12381.G1])(nil)
//	_ encoding.BinaryUnmarshaler = (*Signature[bls12381.G1])(nil)
//)
//
//type ProofOfPossession[S SignatureSubGroup] struct {
//	Value curves.PairingPoint
//
//	_ ds.Incomparable
//}
//
//func (pop *ProofOfPossession[S]) Size() int {
//	if pop.inG1() {
//		return PublicKeySizeInG1
//	}
//	return PublicKeySizeInG2
//}
//
//// Serialise a signature to a byte array in compressed form.
//// See
//// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
//// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
//func (pop *ProofOfPossession[S]) MarshalBinary() ([]byte, error) {
//	out := pop.Value.ToAffineCompressed()
//	return out, nil
//}
//
//// Deserialize a signature from a byte array in compressed form.
//// See
//// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
//// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
//// If successful, it will assign the Signature
//// otherwise it will return an error.
//func (pop *ProofOfPossession[S]) UnmarshalBinary(data []byte) error {
//	size := pop.Size()
//	if len(data) != size {
//		return errs.NewLength("signature must be %d bytes", size)
//	}
//	blob := make([]byte, size)
//	copy(blob, data)
//	g := bls12381.GetSourceSubGroup[S]()
//	p, err := g.Element().FromAffineCompressed(blob)
//	if err != nil {
//		return errs.WrapSerialisation(err, "couldn't deserialize data in a point of G1")
//	}
//	if p.IsAdditiveIdentity() {
//		return errs.NewIsZero("public keys cannot be zero")
//	}
//
//	pop.Value = p.(curves.PairingPoint)
//	return nil
//}
//
//func (*ProofOfPossession[S]) inG1() bool {
//	return bls12381.GetSourceSubGroup[S]().Name() == bls12381.NewG1().Name()
//}
