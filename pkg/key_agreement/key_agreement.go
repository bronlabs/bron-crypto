package key_agreement

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/internal"
)

type Type string

func NewPrivateKey[SKV algebra.UintLike[SKV]](v SKV, t Type) PrivateKey[SKV] {
	return internal.NewPrivateKey(v, t)
}

type PrivateKey[SKV algebra.UintLike[SKV]] interface {
	Type() Type
	base.Transparent[SKV]
}

func NewPublicKey[PKV algebra.AbelianGroupElement[PKV, SKV], SKV algebra.UintLike[SKV]](v PKV, t Type) PublicKey[PKV, SKV] {
	return internal.NewPublicKey(v, t)
}

type PublicKey[PKV algebra.AbelianGroupElement[PKV, SKV], SKV algebra.UintLike[SKV]] interface {
	Type() Type
	base.Transparent[PKV]
}

func NewSharedKey(v []byte, t Type) SharedKey {
	return internal.NewSharedKey(v, t)
}

type SharedKey interface {
	Bytes() []byte
	Type() Type
}
