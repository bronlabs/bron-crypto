package paillier

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
)

func NewPrivateKey(group *znstar.PaillierGroupKnownOrder) (*PrivateKey, error) {
	if group == nil {
		return nil, errs.NewIsNil("m")
	}

	sk := &PrivateKey{
		group: group,
		hp:    numct.NewNat(0),
		hq:    numct.NewNat(0),
	}
	sk.precompute()
	return sk, nil
}

type PrivateKey struct {
	group *znstar.PaillierGroupKnownOrder

	hp *numct.Nat
	hq *numct.Nat

	pk   *PublicKey
	once sync.Once
}

func (sk *PrivateKey) precompute() {
	sk.once.Do(func() {
		sk.Arithmetic().P.Factor.ModInv(sk.hp, sk.Arithmetic().Q.Factor.Nat())
		sk.Arithmetic().P.Factor.ModNeg(sk.hp, sk.hp)
		sk.Arithmetic().Q.Factor.ModInv(sk.hq, sk.Arithmetic().P.Factor.Nat())
		sk.Arithmetic().Q.Factor.ModNeg(sk.hq, sk.hq)
		sk.pk = &PublicKey{group: sk.group.ForgetOrder()}
	})
}

func (sk *PrivateKey) Group() *znstar.PaillierGroupKnownOrder {
	return sk.group
}

func (sk *PrivateKey) Arithmetic() *modular.OddPrimeSquareFactors {
	return sk.group.Arithmetic().(*modular.OddPrimeSquareFactors)
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	sk.precompute()
	return sk.pk
}

func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return sk.group.Equal(other.group)
}

func NewPublicKey(group *znstar.PaillierGroupUnknownOrder) (*PublicKey, error) {
	if group == nil {
		return nil, errs.NewIsNil("group")
	}
	return &PublicKey{
		group: group,
	}, nil
}

type PublicKey struct {
	group *znstar.PaillierGroupUnknownOrder

	plaintextSpace  *PlaintextSpace
	nonceSpace      *NonceSpace
	ciphertextSpace *CiphertextSpace
	once            sync.Once
}

func (pk *PublicKey) Group() *znstar.PaillierGroupUnknownOrder {
	return pk.group
}

func (pk *PublicKey) Equal(other *PublicKey) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return pk.group.Equal(other.group)
}

func (pk *PublicKey) Modulus() *numct.Modulus {
	return pk.group.ModulusCT()
}

func (pk *PublicKey) N() *numct.Modulus {
	return pk.group.N().ModulusCT()
}

func (pk *PublicKey) N2() *numct.Modulus {
	return pk.group.ModulusCT()
}

func (pk *PublicKey) Clone() *PublicKey {
	return &PublicKey{
		group: pk.group,
	}
}

func (pk *PublicKey) HashCode() base.HashCode {
	return pk.N2().HashCode().Combine(pk.N().HashCode())
}

func (pk *PublicKey) cacheSpaces() {
	pk.once.Do(func() {
		var errPlaintext, errNonce, errCiphertext error
		n := pk.group.N()
		nn := pk.group.Modulus()
		pk.plaintextSpace, errPlaintext = NewPlaintextSpace(n)
		pk.nonceSpace, errNonce = NewNonceSpace(n)
		pk.ciphertextSpace, errCiphertext = NewCiphertextSpace(nn, n)
		if errPlaintext != nil {
			panic(errPlaintext)
		}
		if errNonce != nil {
			panic(errNonce)
		}
		if errCiphertext != nil {
			panic(errCiphertext)
		}
	})
}

func (pk *PublicKey) PlaintextSpace() *PlaintextSpace {
	pk.cacheSpaces()
	return pk.plaintextSpace
}

func (pk *PublicKey) NonceSpace() *NonceSpace {
	pk.cacheSpaces()
	return pk.nonceSpace
}

func (pk *PublicKey) CiphertextSpace() *CiphertextSpace {
	pk.cacheSpaces()
	return pk.ciphertextSpace
}
