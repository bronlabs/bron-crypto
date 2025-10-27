package edx25519

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement"
	"golang.org/x/crypto/curve25519"
)

type (
	PrivateKey = key_agreement.PrivateKey[*edwards25519.Scalar]
	PublicKey  = key_agreement.PublicKey[*edwards25519.Point, *edwards25519.Scalar]
	SharedKey  = key_agreement.SharedKey
)

const Type key_agreement.Type = "edX25519"

func DeriveSharedSecretValue(myPrivateKey PrivateKey, otherPartyPublicKey PublicKey) (SharedKey, error) {
	if otherPartyPublicKey == nil || myPrivateKey == nil {
		return nil, errs.NewIsNil("argument")
	}
	if otherPartyPublicKey.Type() != Type || myPrivateKey.Type() != Type {
		return nil, errs.NewValidation("incompatible key types")
	}
	// magic
	out, err := curve25519.X25519(myPrivateKey.Value().Bytes(), otherPartyPublicKey.Value().Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive shared secret")
	}
	return NewSharedKey(out), nil
}

func NewPrivateKey(v *edwards25519.Scalar) PrivateKey {
	return key_agreement.NewPrivateKey(v, Type)
}

func NewPublicKey(v *edwards25519.Point) PublicKey {
	return key_agreement.NewPublicKey(v, Type)
}

func NewSharedKey(v []byte) SharedKey {
	return key_agreement.NewSharedKey(v, Type)
}

// func NewPrivateKey(sk edwards25519.Scalar) Priv {
// 	return &privateKey{v: sk.Bytes()}
// }

// type privateKey struct {
// 	v []byte
// }

// func (sk privateKey) Type() key_agreement.Type {
// 	return Type
// }

// func (sk privateKey) Value() []byte {
// 	return sk.v
// }

// func NewPublicKey(pk edwards25519.Point) *publicKey {
// 	return &publicKey{v: pk.Bytes()}
// }

// type publicKey struct {
// 	v []byte
// }

// func (pk publicKey) Type() key_agreement.Type {
// 	return Type
// }

// func (pk publicKey) Value() []byte {
// 	return pk.v
// }

// func NewSharedKey(v []byte) *sharedKey {
// 	return &sharedKey{v: v}
// }
