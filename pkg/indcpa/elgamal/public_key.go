package elgamal

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa"
)

var (
	_ indcpa.EncryptionKey[*Plaintext2048, *saferith.Nat, *Ciphertext2048]                           = (*PublicKey2048)(nil)
	_ indcpa.HomomorphicEncryptionKey[*Plaintext2048, *saferith.Nat, *Ciphertext2048, *saferith.Nat] = (*PublicKey2048)(nil)
)

type PublicKey2048 struct {
	Y *saferith.Nat
}

func (*PublicKey2048) PlainTextAdd(lhs, rhs *Plaintext2048) (plainText *Plaintext2048, err error) {
	p := new(saferith.Nat).ModMul(lhs.V, rhs.V, Ffdhe2048Modulus)
	return &Plaintext2048{V: p}, nil
}

func (*PublicKey2048) PlainTextSub(lhs, rhs *Plaintext2048) (plainText *Plaintext2048, err error) {
	// TODO implement me
	panic("implement me")
}

func (*PublicKey2048) PlainTextNeg(lhs *Plaintext2048) (plainText *Plaintext2048, err error) {
	// TODO implement me
	panic("implement me")
}

func (*PublicKey2048) PlainTextMul(lhs *Plaintext2048, rhs *saferith.Nat) (plainText *Plaintext2048, err error) {
	// TODO implement me
	panic("implement me")
}

func (*PublicKey2048) NonceAdd(lhs, rhs *saferith.Nat) (nonce *saferith.Nat, err error) {
	r := new(saferith.Nat).ModAdd(lhs, rhs, Ffdhe2048Order)
	return r, nil
}

func (*PublicKey2048) NonceSub(lhs, rhs *saferith.Nat) (nonce *saferith.Nat, err error) {
	r := new(saferith.Nat).ModSub(lhs, rhs, Ffdhe2048Order)
	return r, nil
}

func (*PublicKey2048) NonceNeg(lhs *saferith.Nat) (nonce *saferith.Nat, err error) {
	// TODO implement me
	panic("implement me")
}

func (*PublicKey2048) NonceMul(lhs, rhs *saferith.Nat) (nonce *saferith.Nat, err error) {
	// TODO implement me
	panic("implement me")
}

func (*PublicKey2048) CipherTextAdd(lhs, rhs *Ciphertext2048) (cipherText *Ciphertext2048, err error) {
	c1 := new(saferith.Nat).ModMul(lhs.C1, rhs.C1, Ffdhe2048Modulus)
	c2 := new(saferith.Nat).ModMul(lhs.C2, rhs.C2, Ffdhe2048Modulus)
	return &Ciphertext2048{C1: c1, C2: c2}, nil
}

func (*PublicKey2048) CipherTextAddPlainText(lhs *Ciphertext2048, rhs *Plaintext2048) (cipherText *Ciphertext2048, err error) {
	c2 := new(saferith.Nat).ModMul(lhs.C2, rhs.V, Ffdhe2048Modulus)
	return &Ciphertext2048{C1: lhs.C1.Clone(), C2: c2}, nil
}

func (*PublicKey2048) CipherTextSub(lhs, rhs *Ciphertext2048) (cipherText *Ciphertext2048, err error) {
	rhsC1Inv := new(saferith.Nat).ModInverse(rhs.C1, Ffdhe2048Modulus)
	rhsC2Inv := new(saferith.Nat).ModInverse(rhs.C2, Ffdhe2048Modulus)
	c1 := new(saferith.Nat).ModMul(lhs.C1, rhsC1Inv, Ffdhe2048Modulus)
	c2 := new(saferith.Nat).ModMul(lhs.C2, rhsC2Inv, Ffdhe2048Modulus)
	return &Ciphertext2048{C1: c1, C2: c2}, nil
}

func (*PublicKey2048) CipherTextSubPlainText(lhs *Ciphertext2048, rhs *Plaintext2048) (cipherText *Ciphertext2048, err error) {
	rhsInv := new(saferith.Nat).ModInverse(rhs.V, Ffdhe2048Modulus)
	c2 := new(saferith.Nat).ModMul(lhs.C2, rhsInv, Ffdhe2048Modulus)
	return &Ciphertext2048{C1: lhs.C1.Clone(), C2: c2}, nil
}

func (*PublicKey2048) CipherTextNeg(lhs *Ciphertext2048) (cipherText *Ciphertext2048, err error) {
	// TODO implement me
	panic("implement me")
}

func (*PublicKey2048) CipherTextMul(lhs *Ciphertext2048, rhs *saferith.Nat) (cipherText *Ciphertext2048, err error) {
	// TODO implement me
	panic("implement me")
}

func (*PublicKey2048) RandomNonce(prng io.Reader) (nonce *saferith.Nat, err error) {
	var nonceBytes [(2048 + 128) / 8]byte

	one := new(saferith.Nat).SetUint64(1).Resize(2048)
	minusOne := new(saferith.Nat).Sub(Ffdhe2048Order.Nat(), one, 2048)
	nonce = new(saferith.Nat)
	for {
		_, err = io.ReadFull(prng, nonceBytes[:])
		if err != nil {
			return nil, errs.WrapRandomSample(err, "failed to sample random")
		}

		nonce.SetBytes(nonceBytes[:])
		nonce.Mod(nonce, Ffdhe2048Order)
		if (nonce.EqZero() | nonce.Eq(one) | nonce.Eq(minusOne)) != 0 {
			continue
		}

		return nonce, nil
	}
}

func (pk *PublicKey2048) EncryptWithNonce(plainText *Plaintext2048, nonce *saferith.Nat) (cipherText *Ciphertext2048, err error) {
	s := new(saferith.Nat).Exp(pk.Y, nonce, Ffdhe2048Modulus)
	c1 := new(saferith.Nat).Exp(Ffdhe2048Generator, nonce, Ffdhe2048Modulus)
	c2 := new(saferith.Nat).ModMul(plainText.V, s, Ffdhe2048Modulus)

	return &Ciphertext2048{
		C1: c1,
		C2: c2,
	}, nil
}

func (pk *PublicKey2048) Encrypt(plainText *Plaintext2048, prng io.Reader) (cipherText *Ciphertext2048, nonce *saferith.Nat, err error) {
	nonce, err = pk.RandomNonce(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot generate nonce")
	}

	ciphertext, err := pk.EncryptWithNonce(plainText, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot encrypt")
	}

	return ciphertext, nonce, nil
}

func (*PublicKey2048) CipherTextEqual(lhs, rhs *Ciphertext2048) bool {
	return lhs.C1.Eq(rhs.C1)&lhs.C2.Eq(rhs.C2) == 1
}
