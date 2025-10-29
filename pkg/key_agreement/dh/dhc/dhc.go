package dhc

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement"
)

const Type key_agreement.Type = "ECSVDP-DHC"

type (
	PrivateKey[S algebra.PrimeFieldElement[S]]                                                          = key_agreement.PrivateKey[S]
	PublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = key_agreement.PublicKey[P, S]
	SharedKey[B algebra.FiniteFieldElement[B]]                                                          = key_agreement.SharedKey
)

func DeriveSharedSecret[
	P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S],
](myPrivateKey *PrivateKey[S], otherPartyPublicKey *PublicKey[P, B, S]) (*SharedKey[B], error) {
	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](otherPartyPublicKey.Value().Structure())
	if myPrivateKey == nil || otherPartyPublicKey == nil {
		return nil, errs.NewIsNil("nil key provided")
	}
	if myPrivateKey.Type() != Type || otherPartyPublicKey.Type() != Type {
		return nil, errs.NewValidation("incompatible key types")
	}
	// assumption 1
	if myPrivateKey.Value().IsZero() {
		return nil, errs.NewIsZero("invalid private key")
	}
	if !otherPartyPublicKey.Value().IsTorsionFree() {
		return nil, errs.NewValidation("Public Key not in the prime subgroup")
	}
	// step 1
	k, err := curve.ScalarField().FromCardinal(curve.Cofactor())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get cofactor")
	}
	kInv, err := k.TryInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get inverse")
	}
	t := kInv.Mul(myPrivateKey.Value())
	// step 2
	bigP := otherPartyPublicKey.Value().ScalarMul(k.Mul(t))
	// step 3
	if bigP.IsZero() {
		return nil, errs.NewIsIdentity("invalid public key")
	}
	// step 4
	x, err := bigP.AffineX()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get affine x coordinate")
	}
	// step 5
	return NewSharedKey(x)
}

func NewPrivateKey[S algebra.PrimeFieldElement[S]](v S) (*PrivateKey[S], error) {
	return key_agreement.NewPrivateKey(v, Type)
}

func NewPublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](v P) (*PublicKey[P, B, S], error) {
	return key_agreement.NewPublicKey(v, Type)
}

func NewSharedKey[B algebra.FiniteFieldElement[B]](v B) (*SharedKey[B], error) {
	return key_agreement.NewSharedKey(v.Bytes(), Type)
}
