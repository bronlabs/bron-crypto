package elgamal

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/products"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

type keyGenerator[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	g UnderlyingGroup[E, S]
	z algebra.ZnLike[S]
}

func (kg *keyGenerator[E, S]) Scheme() types.Scheme[encryption.Type] {
	return nil
}

func (kg *keyGenerator[E, S]) Generate(prng types.PRNG, _ any) (*PrivateKey[E, S], error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	g := kg.g.Generator()
	skv, err := kg.z.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to generate private key value")
	}
	pkv := g.ScalarOp(skv)
	pk := &PublicKey[E, S]{pkv}
	sk := &PrivateKey[E, S]{skv, *pk}
	return sk, nil
}

type encrypter[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	g UnderlyingGroup[E, S]
	z algebra.ZnLike[S]
}

func (e *encrypter[E, S]) Scheme() types.Scheme[encryption.Type] {
	return nil
}

func (e *encrypter[E, S]) Encrypt(plaintext *Plaintext[E, S], receiver *PublicKey[E, S], prng types.PRNG, _ any) (*Ciphertext[E, S], *Nonce[E, S], error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	nv, err := e.z.Random(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "failed to generate nonce value")
	}
	nonce := &Nonce[E, S]{nv}
	ciphertext, err := e.EncryptWithNonce(plaintext, receiver, nonce, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to encrypt plaintext")
	}
	return ciphertext, nonce, nil
}

func (e *encrypter[E, S]) EncryptWithNonce(plaintext *Plaintext[E, S], receiver *PublicKey[E, S], nonce *Nonce[E, S], _ any) (*Ciphertext[E, S], error) {
	if plaintext == nil {
		return nil, errs.NewIsNil("plaintext")
	}
	if receiver == nil {
		return nil, errs.NewIsNil("receiver")
	}
	if nonce == nil {
		return nil, errs.NewIsNil("nonce")
	}
	g := e.g.Generator()
	c1 := g.ScalarOp(nonce.Value())
	c2 := receiver.v.ScalarOp(nonce.Value())
	c2.Op(plaintext.Value())
	return &Ciphertext[E, S]{products.NewDirectProductGroupElement(c1, c2)}, nil
}

type decrypter[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	g  UnderlyingGroup[E, S]
	z  algebra.ZnLike[S]
	sk *PrivateKey[E, S]
}

func (d *decrypter[E, S]) Scheme() types.Scheme[encryption.Type] {
	return nil
}

func (d *decrypter[E, S]) PrivateKey() *PrivateKey[E, S] {
	return d.sk
}

func (d *decrypter[E, S]) Decrypt(ciphertext *Ciphertext[E, S], _ any) (*Plaintext[E, S], error) {
	if ciphertext == nil {
		return nil, errs.NewIsNil("ciphertext")
	}
	c1, c2 := ciphertext.Value().Components()
	s := c1.ScalarOp(d.sk.v)
	encoded := c2.Op(s.OpInv())
	return &Plaintext[E, S]{encoded}, nil
}
