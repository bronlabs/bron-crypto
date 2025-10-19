package paillier

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
)

func NewPrivateKey(group znstar.PaillierGroupKnownOrder) (*PrivateKey, error) {
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
	group znstar.PaillierGroupKnownOrder

	hp *numct.Nat
	hq *numct.Nat

	pk   *PublicKey
	once sync.Once
}

func (sk *PrivateKey) precompute() {
	sk.once.Do(func() {
		sk.group.Arithmetic().P.Factor.ModInv(sk.hp, sk.group.Arithmetic().Q.Factor.Nat())
		sk.group.Arithmetic().P.Factor.ModNeg(sk.hp, sk.hp)
		sk.group.Arithmetic().Q.Factor.ModInv(sk.hq, sk.group.Arithmetic().P.Factor.Nat())
		sk.group.Arithmetic().Q.Factor.ModNeg(sk.hq, sk.hq)
		sk.pk = &PublicKey{group: sk.group.ForgetOrder()}
	})
}

func (sk *PrivateKey) Group() znstar.PaillierGroupKnownOrder {
	return sk.group
}

func (sk *PrivateKey) Arithmetic() *modular.OddPrimeSquareFactors {
	return sk.group.Arithmetic()
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	sk.precompute()
	return sk.pk
}

func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return znstar.PaillierGroupsAreEqual(sk.group, other.group)
}

func NewPublicKey(group znstar.PaillierGroup) (*PublicKey, error) {
	if group == nil {
		return nil, errs.NewIsNil("group")
	}
	return &PublicKey{
		group: group,
	}, nil
}

type PublicKey struct {
	group znstar.PaillierGroup

	plaintextSpace  *PlaintextSpace
	nonceSpace      *NonceSpace
	ciphertextSpace *CiphertextSpace
	once            sync.Once
}

func (pk *PublicKey) Group() znstar.PaillierGroup {
	return pk.group
}

func (pk *PublicKey) Equal(other *PublicKey) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return znstar.PaillierGroupsAreEqual(pk.group, other.group)
}

func (pk *PublicKey) Modulus() numct.Modulus {
	return pk.group.ModulusCT()
}

func (pk *PublicKey) N() numct.Modulus {
	return pk.group.N().ModulusCT()
}

func (pk *PublicKey) N2() numct.Modulus {
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
		pk.nonceSpace, errNonce = NewNonceSpace(nn)
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
