package dhc

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement"
)

// Type is the type identifier for the ECSVDP-DHC key agreement scheme.
const Type key_agreement.Type = "ECSVDP-DHC"

type (
	// PrivateKey represents a private key in the DHC key agreement scheme.
	PrivateKey struct {
		v []byte
	}
	// ExtendedPrivateKey represents an extended private key with scalar value.
	ExtendedPrivateKey[S algebra.PrimeFieldElement[S]] struct {
		PrivateKey

		s S
	}
	// PublicKey represents a public key in the DHC key agreement scheme.
	PublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = key_agreement.PublicKey[P, S]
	// SharedKey represents a shared key in the DHC key agreement scheme.
	SharedKey[B algebra.FiniteFieldElement[B]] = key_agreement.SharedKey
)

// DeriveSharedSecret derives a shared secret using the DHC key agreement scheme.
func DeriveSharedSecret[
	P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S],
](myPrivateKey *ExtendedPrivateKey[S], otherPartyPublicKey *PublicKey[P, B, S]) (*SharedKey[B], error) {
	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](otherPartyPublicKey.Value().Structure())
	if myPrivateKey == nil || otherPartyPublicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("nil key provided")
	}
	if myPrivateKey.Type() != Type || otherPartyPublicKey.Type() != Type {
		return nil, ErrInvalidArgument.WithMessage("incompatible key types")
	}
	// assumption 1
	if myPrivateKey.Value().IsZero() {
		return nil, ErrInvalidSubGroup.WithMessage("invalid private key")
	}
	if !otherPartyPublicKey.Value().IsTorsionFree() {
		return nil, ErrInvalidSubGroup.WithMessage("Public Key not in the prime subgroup")
	}
	// step 1
	k, err := curve.ScalarField().FromCardinal(curve.Cofactor())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot get cofactor")
	}
	kInv, err := k.TryInv()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot get inverse")
	}
	t := kInv.Mul(myPrivateKey.Value())
	// step 2
	bigP := otherPartyPublicKey.Value().ScalarMul(k.Mul(t))
	// step 3
	if bigP.IsZero() {
		return nil, ErrInvalidSubGroup.WithMessage("invalid public key")
	}
	// step 4
	x, err := bigP.AffineX()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot get affine x coordinate")
	}
	// step 5
	return NewSharedKey(x)
}

// SerialiseExtendedPrivateKey serialises an extended private key to bytes.
func SerialiseExtendedPrivateKey[S algebra.PrimeFieldElement[S]](sk *ExtendedPrivateKey[S]) ([]byte, error) {
	if sk == nil {
		return nil, ErrInvalidArgument.WithMessage("nil extended private key")
	}
	return sk.v, nil
}

// SerialisePublicKey serialises a public key to bytes.
func SerialisePublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pk *PublicKey[P, B, S]) ([]byte, error) {
	if pk == nil {
		return nil, ErrInvalidArgument.WithMessage("nil public key")
	}
	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](pk.Value().Structure())
	var out []byte
	if isFromCurve25519(curve.Name()) || isFromEdwards25519(curve.Name()) {
		out = pk.Value().ToCompressed()
	} else {
		out = pk.Value().ToUncompressed()
	}
	return out, nil
}

// SerialiseSharedKey serialises a shared key to bytes.
func SerialiseSharedKey[B algebra.FiniteFieldElement[B]](k *SharedKey[B]) ([]byte, error) {
	if k == nil {
		return nil, ErrInvalidArgument.WithMessage("nil shared key")
	}
	return k.Bytes(), nil
}

// NewPrivateKey creates a new PrivateKey instance.
func NewPrivateKey(v []byte) (*PrivateKey, error) {
	if ct.SliceIsZero(v) == ct.True {
		return nil, ErrInvalidArgument.WithMessage("private key bytes are zero")
	}
	return &PrivateKey{v: slices.Clone(v)}, nil
}

// Value returns the value of the private key.
func (sk *PrivateKey) Value() []byte {
	return sk.v
}

// Type returns the type of the private key.
func (*PrivateKey) Type() key_agreement.Type {
	return Type
}

// Equal checks if two private keys are equal.
func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	if sk == nil && other == nil {
		return sk == other
	}
	return ct.SliceEqual(sk.v, other.v) == ct.True
}

// ExtendPrivateKey extends a PrivateKey to an ExtendedPrivateKey with scalar value.
// If scalar field is from Curve25519, the private key bytes are clamped as per RFC 7748.
func ExtendPrivateKey[S algebra.PrimeFieldElement[S]](sk *PrivateKey, sf algebra.PrimeField[S]) (*ExtendedPrivateKey[S], error) {
	if sk == nil {
		return nil, ErrInvalidArgument.WithMessage("nil private key")
	}
	if sf == nil {
		return nil, ErrInvalidArgument.WithMessage("nil sf")
	}
	var s S
	var err error
	if isFromCurve25519(sf.Name()) {
		sf := algebra.StructureMustBeAs[interface {
			algebra.PrimeField[S]
			FromClampedBytes([]byte) (S, error)
		}](sf)
		s, err = sf.FromClampedBytes(sk.Value()) // Note that the input to FromClampedBytes is little-endian
	} else {
		s, err = sf.FromBytes(sk.Value())
	}
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not derive extended private key")
	}
	if s.IsZero() {
		return nil, ErrInvalidSubGroup.WithMessage("invalid private key scalar")
	}
	return &ExtendedPrivateKey[S]{PrivateKey: *sk, s: s}, nil
}

// Value returns the scalar value of the extended private key.
func (esk *ExtendedPrivateKey[S]) Value() S {
	return esk.s
}

// Bytes returns the byte representation of the extended private key.
func (esk *ExtendedPrivateKey[S]) Bytes() []byte {
	return esk.v // this may be little-endian if from X25519
}

// Equal checks if two extended private keys are equal.
func (esk *ExtendedPrivateKey[S]) Equal(other *ExtendedPrivateKey[S]) bool {
	if esk == nil && other == nil {
		return esk == other
	}
	return ct.SliceEqual(esk.v, other.v) == ct.True && esk.s.Equal(other.s)
}

// NewPublicKey creates a new PublicKey instance.
func NewPublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](v P) (*PublicKey[P, B, S], error) {
	out, err := key_agreement.NewPublicKey(v, Type)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create public key")
	}
	return out, nil
}

// NewSharedKey creates a new SharedKey instance.
func NewSharedKey[B algebra.FiniteFieldElement[B]](v B) (*SharedKey[B], error) {
	var b []byte
	if isFromCurve25519(v.Structure().Name()) {
		b = sliceutils.Reversed(v.Bytes()) // X25519 expects little-endian
	} else {
		b = v.Bytes()
	}
	out, err := key_agreement.NewSharedKey(b, Type)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create shared key")
	}
	return out, nil
}

func isFromCurve25519(name string) bool {
	switch name {
	case curve25519.PrimeCurveName, curve25519.ScalarFieldName, curve25519.BaseFieldName:
		return true
	default:
		return false
	}
}

func isFromEdwards25519(name string) bool {
	switch name {
	case edwards25519.PrimeCurveName, edwards25519.ScalarFieldName, edwards25519.BaseFieldName:
		return true
	default:
		return false
	}
}

var (
	ErrInvalidArgument = errs2.New("invalid argument")
	ErrInvalidSubGroup = errs2.New("element not in correct subgroup")
	ErrValidation      = errs2.New("validation error")
)
