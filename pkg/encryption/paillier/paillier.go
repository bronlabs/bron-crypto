// Package paillier implements the Paillier cryptosystem, an additive homomorphic
// public-key encryption scheme. It supports homomorphic addition of ciphertexts
// and scalar multiplication of ciphertexts by plaintexts.
package paillier

import (
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

// Name is the identifier for the Paillier encryption scheme.
const (
	Name   encryption.Name = "paillier"
	KeyLen                 = znstar.PaillierKeyLen
)

// NewScheme returns a new Paillier encryption scheme instance.
func NewScheme() *Scheme {
	return &Scheme{}
}

// Scheme represents the Paillier encryption scheme and provides factory methods
// for creating key generators, encrypters, and decrypters.
type Scheme struct{}

// Name returns the identifier for the Paillier encryption scheme.
func (*Scheme) Name() encryption.Name {
	return Name
}

// Keygen creates a new key generator with the given options.
func (*Scheme) Keygen(opts ...KeyGeneratorOption) (*KeyGenerator, error) {
	kg := &KeyGenerator{
		bits: KeyLen,
	}
	for _, opt := range opts {
		if err := opt(kg); err != nil {
			return nil, errs.Wrap(err)
		}
	}
	return kg, nil
}

// Encrypter creates a new encrypter with the given options.
func (*Scheme) Encrypter(opts ...EncrypterOption) (*Encrypter, error) {
	e := &Encrypter{}
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, errs.Wrap(err)
		}
	}
	return e, nil
}

// SelfEncrypter creates a new self-encrypter for the given private key.
// A self-encrypter encrypts messages to the owner of the private key,
// using CRT optimizations for faster encryption.
func (*Scheme) SelfEncrypter(sk *PrivateKey, opts ...SelfEncrypterOption) (*SelfEncrypter, error) {
	if sk == nil {
		return nil, ErrInvalidArgument.WithStackFrame()
	}
	se := &SelfEncrypter{sk: sk, pk: sk.PublicKey()}
	se.pk.cacheSpaces()
	for _, opt := range opts {
		if err := opt(se); err != nil {
			return nil, errs.Wrap(err)
		}
	}
	return se, nil
}

// Decrypter creates a new decrypter for the given private key.
func (*Scheme) Decrypter(sk *PrivateKey, opts ...DecrypterOption) (*Decrypter, error) {
	if sk == nil {
		return nil, ErrInvalidArgument.WithStackFrame()
	}
	d := &Decrypter{sk: sk}
	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, errs.Wrap(err)
		}
	}
	return d, nil
}

func lp(sk *PrivateKey, x *numct.Nat) {
	sk.Arithmetic().P.Squared.ModSub(x, x, numct.NatOne())
	sk.Arithmetic().P.Factor.Quo(x, x)
}

func lq(sk *PrivateKey, x *numct.Nat) {
	sk.Arithmetic().Q.Squared.ModSub(x, x, numct.NatOne())
	sk.Arithmetic().Q.Factor.Quo(x, x)
}

var (
	ErrInvalidArgument = errs.New("invalid argument")
	ErrInvalidRange    = errs.New("invalid range")
)
