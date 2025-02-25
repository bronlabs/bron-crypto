package elgamal

import (
	"io"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa"
)

var (
	_ indcpa.DecryptionKey[*Plaintext2048, *saferith.Nat, *Ciphertext2048, *PublicKey2048] = (*SecretKey2048)(nil)
)

type SecretKey2048 struct {
	PublicKey2048
	X *saferith.Nat
}

func KeyGen(prng io.Reader) (sk *SecretKey2048, pk *PublicKey2048, err error) {
	var xBytes [(2048 + 128) / 8]byte

	one := new(saferith.Nat).SetUint64(1).Resize(2048)
	minusOne := new(saferith.Nat).Sub(Ffdhe2048Order.Nat(), one, 2048)
	x := new(saferith.Nat)
	for {
		_, err = io.ReadFull(prng, xBytes[:])
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "cannot sample")
		}

		x.SetBytes(xBytes[:])
		x.Mod(x, Ffdhe2048Order)
		if (x.EqZero() | x.Eq(one) | x.Eq(minusOne)) != 0 {
			continue
		}
		break
	}

	y := new(saferith.Nat).Exp(Ffdhe2048Generator, x, Ffdhe2048Modulus)
	pk = &PublicKey2048{
		Y: y,
	}
	sk = &SecretKey2048{
		PublicKey2048: *pk,
		X:             x,
	}

	return sk, pk, nil
}

func (sk *SecretKey2048) ToEncryptionKey() (encryptionKey *PublicKey2048, err error) {
	return &sk.PublicKey2048, nil
}

func (sk *SecretKey2048) Decrypt(cipherText *Ciphertext2048) (plainText *Plaintext2048, err error) {
	s := new(saferith.Nat).Exp(cipherText.C1, sk.X, Ffdhe2048Modulus)
	sInv := new(saferith.Nat).ModInverse(s, Ffdhe2048Modulus)
	m := new(saferith.Nat).ModMul(cipherText.C2, sInv, Ffdhe2048Modulus)
	if big.Jacobi(m.Big(), Ffdhe2048Modulus.Big()) != 1 {
		return nil, errs.NewFailed("invalid ciphertext")
	}

	return &Plaintext2048{V: m}, nil
}

func (*SecretKey2048) Open(_ *Ciphertext2048) (plainText *Plaintext2048, nonce *saferith.Nat, err error) {
	return nil, nil, errs.NewFailed("unsupported operation")
}
