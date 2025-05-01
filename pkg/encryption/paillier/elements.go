package paillier

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num"
)

type PublicKey struct {
	n *num.Int
}

func (pk *PublicKey) Value() *num.Int {
	return pk.n
}

func (pk *PublicKey) Equal(x *PublicKey) bool {
	return pk.n.Equal(x.n)
}

func (pk *PublicKey) Clone() *PublicKey {
	return &PublicKey{pk.n.Clone()}
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	panic("implement me")
}

func (pk *PublicKey) UnmarshalBinary(input []byte) error {
	panic("implement me")
}

type PrivateKey struct {
	lambda *num.Int
	mu     *num.Uint
	public *PublicKey
}

func (sk *PrivateKey) Public() *PublicKey {
	return sk.public
}

func (sk *PrivateKey) Equal(x *PrivateKey) bool {
	return sk.lambda.Equal(x.lambda) && sk.mu.Equal(x.mu) && sk.public.Equal(x.public)
}

func (sk *PrivateKey) Clone() *PrivateKey {
	return &PrivateKey{
		lambda: sk.lambda.Clone(),
		mu:     sk.mu.Clone(),
		public: sk.public.Clone(),
	}
}

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	panic("implement me")
}

func (sk *PrivateKey) UnmarshalBinary(input []byte) error {
	panic("implement me")
}
