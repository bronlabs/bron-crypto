package bls

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"

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

//type KeySubGroup = bls12381.SourceSubGroups
//
//var (
//	_ encoding.BinaryMarshaler   = (*PrivateKey[bls12381.G1])(nil)
//	_ encoding.BinaryUnmarshaler = (*PrivateKey[bls12381.G1])(nil)
//
//	_ encoding.BinaryMarshaler   = (*PrivateKey[bls12381.G2])(nil)
//	_ encoding.BinaryUnmarshaler = (*PrivateKey[bls12381.G2])(nil)
//)

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

//// MarshalBinary serialises a secret key to raw bytes.
//func (sk *PrivateKey[P, B, S]) MarshalBinary() ([]byte, error) {
//	bytes := sk.d.Bytes()
//	return sliceutils.Reverse(bytes), nil
//}

// TODO(aalireza): how to compute public key if it's not serialized and no access to curve
// TODO(aalireza): my two cents - we should not use Marshal/Unmarshal to match the format, marshal/unmarshal is, well... for marshalling only
// it can be unmarshalled later (e.g. cold storage) not to match the format.
//// UnmarshalBinary deserializes a secret key from raw bytes
//// Cannot be zero. Must be 32 bytes and cannot be all zeroes.
//// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03#section-2.3
//func (sk *PrivateKey[P, B, S]) UnmarshalBinary(data []byte) error {
//	if len(data) != SecretKeySize {
//		return errs.NewLength("secret key must be %d bytes", SecretKeySize)
//	}
//	zeros := make([]byte, len(data))
//	if subtle.ConstantTimeCompare(data, zeros) == 1 {
//		return errs.NewIsZero("secret key cannot be zero")
//	}
//	var bb [bls12381Impl.FqBytes]byte
//	copy(bb[:], bitstring.ReverseBytes(data))
//
//	sk.d = &bls12381.Scalar{G: bls12381.GetSourceSubGroup[K]()}
//	ok := sk.d.V.SetBytes(bb[:])
//	if ok != 1 {
//		return errs.NewSerialisation("couldn't set bytes")
//	}
//
//	Y := sk.d.ScalarField().CurveTrait().ScalarBaseMult(sk.d).(curves.PairingPoint)
//	sk.PublicKey = &PublicKey[K]{
//		Y: Y,
//	}
//
//	return nil
//}

//var (
//	_ encoding.BinaryMarshaler   = (*PublicKey[bls12381.G1])(nil)
//	_ encoding.BinaryUnmarshaler = (*PublicKey[bls12381.G1])(nil)
//
//	_ encoding.BinaryMarshaler   = (*PublicKey[bls12381.G2])(nil)
//	_ encoding.BinaryUnmarshaler = (*PublicKey[bls12381.G2])(nil)
//)

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
// Note that if the RogueKeyPreventionScheme is POP, this public key must be accompanied with a proof of possession.
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

//// MarshalBinary Serialises a public key to a byte array in compressed form.
//// See
//// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
//// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
//func (pk *PublicKey[P, B, S]) MarshalBinary() ([]byte, error) {
//	out := pk.Y.ToAffineCompressed()
//	return out, nil
//}

// TODO(aalireza): same thing here, how to deserialize PK
//// UnmarshalBinary Deserializes a public key from a byte array in compressed form.
//// See
//// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
//// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
//// If successful, it will assign the public key
//// otherwise it will return an error.
//func (pk *PublicKey[K]) UnmarshalBinary(data []byte) error {
//	size := pk.Size()
//	if len(data) != size {
//		return errs.NewLength("public key must be %d bytes", size)
//	}
//	blob := make([]byte, size)
//	copy(blob, data)
//	g := bls12381.GetSourceSubGroup[K]()
//	p, err := g.Element().FromAffineCompressed(blob)
//	if err != nil {
//		return errs.WrapSerialisation(err, "couldn't deserialize data in a point of G1")
//	}
//	if p.IsAdditiveIdentity() {
//		return errs.NewIsZero("public keys cannot be zero")
//	}
//	pk.Y = p.(curves.PairingPoint)
//	return nil
//}

//func (*PublicKey[K]) InG1() bool {
//	return bls12381.GetSourceSubGroup[K]().Name() == bls12381.NewG1().Name()
//}
//
//type SignatureSubGroup = KeySubGroup
//
//var (
//	_ encoding.BinaryMarshaler   = (*Signature[bls12381.G2])(nil)
//	_ encoding.BinaryUnmarshaler = (*Signature[bls12381.G2])(nil)
//
//	_ encoding.BinaryMarshaler   = (*Signature[bls12381.G1])(nil)
//	_ encoding.BinaryUnmarshaler = (*Signature[bls12381.G1])(nil)
//)

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

// TODO(aalireza): how to deserialize it?
// // UnmarshalBinary Deserializes a signature from a byte array in compressed form.
// // See
// // https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// // https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// // If successful, it will assign the Signature
// // otherwise it will return an error.
//
//	func (sig *Signature[S]) UnmarshalBinary(data []byte) error {
//		size := sig.Size()
//		if len(data) != size {
//			return errs.NewLength("signature must be %d bytes", size)
//		}
//		blob := make([]byte, size)
//		copy(blob, data)
//		g := bls12381.GetSourceSubGroup[S]()
//		p, err := g.Element().FromAffineCompressed(blob)
//		if err != nil {
//			return errs.WrapSerialisation(err, "couldn't deserialize data in a point of G1")
//		}
//		if p.IsAdditiveIdentity() {
//			return errs.NewIsZero("signatures cannot be zero")
//		}
//
//		sig.Value = p.(curves.PairingPoint)
//		return nil
//	}
//
//	func (*Signature[S]) inG1() bool {
//		return bls12381.GetSourceSubGroup[S]().Name() == bls12381.NewG1().Name()
//	}
//
// // type aliasing of generic types is not supported. So, sitll have to copy identical stuff.
// var (
//
//	_ encoding.BinaryMarshaler   = (*Signature[bls12381.G2])(nil)
//	_ encoding.BinaryUnmarshaler = (*Signature[bls12381.G2])(nil)
//
//	_ encoding.BinaryMarshaler   = (*Signature[bls12381.G1])(nil)
//	_ encoding.BinaryUnmarshaler = (*Signature[bls12381.G1])(nil)
//
// )
type ProofOfPossession[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] struct {
	Value P

	_ ds.Incomparable
}

func (pop *ProofOfPossession[P, B, S]) Size() int {
	curve, _ := curves.GetCurve(pop.Value)
	return curve.BaseField().ElementSize()
}

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
