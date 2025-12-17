package paillier

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
)

// NewPrivateKey creates a new Paillier private key from a Paillier group with known order.
// The group must contain the factorization n = p * q where p and q are distinct odd primes.
func NewPrivateKey(group *znstar.PaillierGroupKnownOrder) (*PrivateKey, error) {
	if group == nil {
		return nil, ErrInvalidArgument.WithStackFrame()
	}

	sk := &PrivateKey{ //nolint:exhaustruct // other fields initialised later
		group: group,
		hp:    numct.NewNat(0),
		hq:    numct.NewNat(0),
	}
	sk.precompute()
	return sk, nil
}

// PrivateKey represents a Paillier private key containing the prime factorization
// of the modulus n = p * q. It enables efficient decryption using CRT.
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
		sk.pk = &PublicKey{group: sk.group.ForgetOrder()} //nolint:exhaustruct // other fields initialised later
	})
}

// Group returns the underlying Paillier group with known order.
func (sk *PrivateKey) Group() *znstar.PaillierGroupKnownOrder {
	return sk.group
}

// Arithmetic returns the modular arithmetic instance for efficient computations mod n².
func (sk *PrivateKey) Arithmetic() *modular.OddPrimeSquareFactors {
	out, ok := sk.group.Arithmetic().(*modular.OddPrimeSquareFactors)
	if !ok {
		panic("expected modular.OddPrimeSquareFactors")
	}
	return out
}

// PublicKey derives and returns the corresponding public key.
func (sk *PrivateKey) PublicKey() *PublicKey {
	sk.precompute()
	return sk.pk
}

// Equal returns true if both private keys are equal.
func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return sk.group.Equal(other.group)
}

// NewPublicKey creates a new Paillier public key from a Paillier group with unknown order.
// The public key contains only the modulus n, without knowledge of its factorization.
func NewPublicKey(group *znstar.PaillierGroupUnknownOrder) (*PublicKey, error) {
	if group == nil {
		return nil, ErrInvalidArgument.WithStackFrame()
	}
	return &PublicKey{ //nolint:exhaustruct // other fields initialised later
		group: group,
	}, nil
}

// PublicKey represents a Paillier public key containing the modulus n.
// It can be used for encryption but not decryption.
type PublicKey struct {
	group *znstar.PaillierGroupUnknownOrder

	plaintextSpace  *PlaintextSpace
	nonceSpace      *NonceSpace
	ciphertextSpace *CiphertextSpace
	once            sync.Once
}

// Group returns the underlying Paillier group with unknown order.
func (pk *PublicKey) Group() *znstar.PaillierGroupUnknownOrder {
	return pk.group
}

// Equal returns true if both public keys are equal.
func (pk *PublicKey) Equal(other *PublicKey) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return pk.group.Equal(other.group)
}

// Modulus returns the modulus n² as a constant-time modulus.
func (pk *PublicKey) Modulus() *numct.Modulus {
	return pk.group.ModulusCT()
}

// N returns the modulus n as a constant-time modulus.
func (pk *PublicKey) N() *numct.Modulus {
	return pk.group.N().ModulusCT()
}

// N2 returns the modulus n² as a constant-time modulus.
func (pk *PublicKey) N2() *numct.Modulus {
	return pk.group.ModulusCT()
}

// Clone returns a shallow copy of the public key.
func (pk *PublicKey) Clone() *PublicKey {
	return &PublicKey{ //nolint:exhaustruct // other fields initialised later
		group: pk.group,
	}
}

// HashCode returns a hash code for the public key.
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

// PlaintextSpace returns the plaintext space Z_n for this public key.
func (pk *PublicKey) PlaintextSpace() *PlaintextSpace {
	pk.cacheSpaces()
	return pk.plaintextSpace
}

// NonceSpace returns the nonce space (Z_n)* for this public key.
func (pk *PublicKey) NonceSpace() *NonceSpace {
	pk.cacheSpaces()
	return pk.nonceSpace
}

// CiphertextSpace returns the ciphertext space (Z_n²)* for this public key.
func (pk *PublicKey) CiphertextSpace() *CiphertextSpace {
	pk.cacheSpaces()
	return pk.ciphertextSpace
}
