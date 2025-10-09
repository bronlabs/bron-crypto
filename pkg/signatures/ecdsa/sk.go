package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type PrivateKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	sk S
	pk *PublicKey[P, B, S]
}

func NewPrivateKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](sk S, pk *PublicKey[P, B, S]) (*PrivateKey[P, B, S], error) {
	if pk == nil {
		return nil, errs.NewIsNil("public key")
	}
	if sk.IsZero() {
		return nil, errs.NewFailed("secret key is zero")
	}
	curve, err := algebra.StructureAs[Curve[P, B, S]](pk.Value().Structure())
	if err != nil {
		return nil, errs.WrapFailed(err, "curve structure is not supported")
	}
	if !curve.ScalarBaseMul(sk).Equal(pk.Value()) {
		return nil, errs.NewFailed("private key doesn't match public key")
	}

	key := &PrivateKey[P, B, S]{
		sk: sk,
		pk: pk,
	}
	return key, nil
}

func (sk *PrivateKey[P, B, S]) Value() S {
	return sk.sk
}

func (sk *PrivateKey[P, B, S]) PublicKey() *PublicKey[P, B, S] {
	return sk.pk
}

func (sk *PrivateKey[P, B, S]) Equal(rhs *PrivateKey[P, B, S]) bool {
	if sk == nil || rhs == nil {
		return sk == rhs
	}
	return sk.sk.Equal(rhs.sk)
}

func (sk *PrivateKey[P, B, S]) Clone() *PrivateKey[P, B, S] {
	if sk == nil {
		return nil
	}

	clone := &PrivateKey[P, B, S]{
		sk: sk.sk.Clone(),
		pk: sk.pk.Clone(),
	}
	return clone
}

func (sk *PrivateKey[P, B, S]) ToElliptic() *nativeEcdsa.PrivateKey {
	nativeSk := &nativeEcdsa.PrivateKey{
		PublicKey: *sk.pk.ToElliptic(),
		D:         sk.sk.Cardinal().Big(),
	}

	return nativeSk
}
