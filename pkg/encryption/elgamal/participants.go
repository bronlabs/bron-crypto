package elgamal

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

type KeyGeneratorOption[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] = func(*KeyGenerator[E, S]) error

type KeyGenerator[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	g UnderlyingGroup[E, S]
	z algebra.ZnLike[S]
}

func (kg *KeyGenerator[E, S]) Generate(prng io.Reader) (*PrivateKey[E, S], *PublicKey[E, S], error) {
	if kg == nil {
		return nil, nil, errs.NewIsNil("key generator")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	g := kg.g.Generator()
	skv, err := algebrautils.RandomNonIdentity(kg.z, prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "failed to generate private key value")
	}
	pkv := g.ScalarOp(skv)
	pk := &PublicKey[E, S]{pkv}
	sk := &PrivateKey[E, S]{skv, *pk}
	return sk, pk, nil
}

type EncrypterOption[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] = func(*Encrypter[E, S]) error

type Encrypter[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	g       UnderlyingGroup[E, S]
	z       algebra.ZnLike[S]
	ctSpace *constructions.FiniteDirectSumModule[UnderlyingGroup[E, S], E, S]
}

func (e *Encrypter[E, S]) Encrypt(plaintext *Plaintext[E, S], receiver *PublicKey[E, S], prng io.Reader) (*Ciphertext[E, S], *Nonce[E, S], error) {
	if e == nil {
		return nil, nil, errs.NewIsNil("encrypter")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if receiver == nil {
		return nil, nil, errs.NewIsNil("receiver")
	}
	if plaintext == nil {
		return nil, nil, errs.NewIsNil("plaintext")
	}
	nv, err := algebrautils.RandomNonIdentity(e.z, prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "failed to generate nonce value")
	}
	nonce := &Nonce[E, S]{nv}
	ciphertext, err := e.EncryptWithNonce(plaintext, receiver, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to encrypt plaintext")
	}
	return ciphertext, nonce, nil
}

func (e *Encrypter[E, S]) EncryptWithNonce(plaintext *Plaintext[E, S], receiver *PublicKey[E, S], nonce *Nonce[E, S]) (*Ciphertext[E, S], error) {
	if e == nil {
		return nil, errs.NewIsNil("encrypter")
	}
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
	out, err := e.ctSpace.New(c1, c2)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ciphertext space")
	}
	return &Ciphertext[E, S]{out}, nil
}

type DecrypterOption[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] = func(*Decrypter[E, S]) error

type Decrypter[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	sk *PrivateKey[E, S]
}

func (d *Decrypter[E, S]) Decrypt(ciphertext *Ciphertext[E, S]) (*Plaintext[E, S], error) {
	if d == nil {
		return nil, errs.NewIsNil("decrypter")
	}
	if ciphertext == nil {
		return nil, errs.NewIsNil("ciphertext")
	}
	cs := ciphertext.Value().Components()
	c1, c2 := cs[0], cs[1]
	s := c1.ScalarOp(d.sk.v)
	encoded := c2.Op(s.OpInv())
	return &Plaintext[E, S]{encoded}, nil
}

func (d *Decrypter[E, S]) DecryptWithNonce(ciphertext *Ciphertext[E, S], nonce *Nonce[E, S]) (*Plaintext[E, S], error) {
	if d == nil {
		return nil, errs.NewIsNil("decrypter")
	}
	if ciphertext == nil {
		return nil, errs.NewIsNil("ciphertext")
	}
	if nonce == nil {
		return nil, errs.NewIsNil("nonce")
	}
	// ciphertext is (c1, c2) = (g^r, m * h^r) = (g^r, m * (g^x)^r)

	// Compute h^r = (g^x)^r
	h := d.sk.pk.v
	hr := h.ScalarOp(nonce.Value())

	// m = c2 · (h^r)^{-1}
	c2 := ciphertext.Value().Components()[1]
	m := c2.Op(hr.OpInv())

	return &Plaintext[E, S]{m}, nil
}
