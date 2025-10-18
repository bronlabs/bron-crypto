package paillier

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

const Name encryption.Name = "paillier"

func NewScheme() *Scheme {
	return &Scheme{}
}

type Scheme struct{}

func (s *Scheme) Name() encryption.Name {
	return Name
}

func (s *Scheme) Keygen(opts ...KeyGeneratorOption) (*KeyGenerator, error) {
	kg := &KeyGenerator{
		// TODO: correspond to constants in base package
		bits: 2048,
	}
	for _, opt := range opts {
		if err := opt(kg); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply key generator option")
		}
	}
	return kg, nil
}

func (s *Scheme) Encrypter(opts ...EncrypterOption) (*Encrypter, error) {
	e := &Encrypter{}
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply encrypter option")
		}
	}
	return e, nil
}

func (s *Scheme) SelfEncrypter(sk *PrivateKey, opts ...SelfEncrypterOption) (*SelfEncrypter, error) {
	if sk == nil {
		return nil, errs.NewIsNil("sk")
	}
	se := &SelfEncrypter{sk: sk, pk: sk.PublicKey()}
	se.pk.cacheSpaces()
	for _, opt := range opts {
		if err := opt(se); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply self-encrypter option")
		}
	}
	return se, nil
}

func (s *Scheme) Decrypter(sk *PrivateKey, opts ...DecrypterOption) (*Decrypter, error) {
	if sk == nil {
		return nil, errs.NewIsNil("sk")
	}
	d := &Decrypter{sk: sk}
	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply decrypter option")
		}
	}
	return d, nil
}

func Phi(receiver *PublicKey, plaintext *Plaintext) znstar.Unit {
	out, err := receiver.group.Phi(plaintext.ValueCT())
	if err != nil {
		panic(err)
	}
	return out
}

func lp(sk *PrivateKey, x *numct.Nat) {
	sk.Arithmetic().P.Squared.ModSub(x, x, numct.NatOne())
	sk.Arithmetic().P.Factor.Quo(x, x)
}

func lq(sk *PrivateKey, x *numct.Nat) {
	sk.Arithmetic().Q.Squared.ModSub(x, x, numct.NatOne())
	sk.Arithmetic().Q.Factor.Quo(x, x)
}
