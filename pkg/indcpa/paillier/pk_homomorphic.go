package paillier

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/modular"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa"
)

var (
	_ indcpa.HomomorphicEncryptionKey[*PlainText, *Nonce, *CipherText, *Scalar] = (*PublicKey)(nil)
)

func (pk *PublicKey) PlainTextAdd(lhs, rhs *PlainText) (plainText *PlainText, err error) {
	if !pk.validPlaintext(lhs) {
		return nil, errs.NewValidation("invalid plaintext")
	}
	if !pk.validPlaintext(lhs) {
		return nil, errs.NewValidation("invalid plaintext")
	}

	l := lhs.Mod(pk.N)
	r := rhs.Mod(pk.N)
	l.ModAdd(l, r, pk.N)
	return new(saferith.Int).SetModSymmetric(l, pk.N), nil
}

func (pk *PublicKey) PlainTextSub(lhs, rhs *PlainText) (plainText *PlainText, err error) {
	if !pk.validPlaintext(lhs) {
		return nil, errs.NewValidation("invalid plaintext")
	}
	if !pk.validPlaintext(lhs) {
		return nil, errs.NewValidation("invalid plaintext")
	}

	l := lhs.Mod(pk.N)
	r := rhs.Mod(pk.N)
	l.ModSub(l, r, pk.N)
	return new(saferith.Int).SetModSymmetric(l, pk.N), nil
}

func (pk *PublicKey) PlainTextNeg(lhs *PlainText) (plainText *PlainText, err error) {
	if !pk.validPlaintext(lhs) {
		return nil, errs.NewValidation("invalid plaintext")
	}

	return lhs.Clone().Neg(1), nil
}

func (pk *PublicKey) PlainTextMul(lhs *PlainText, rhs *Scalar) (plainText *PlainText, err error) {
	if !pk.validPlaintext(lhs) {
		return nil, errs.NewValidation("invalid plaintext")
	}
	if !pk.validScalar(rhs) {
		return nil, errs.NewValidation("invalid scalar")
	}

	l := lhs.Mod(pk.N)
	r := rhs.Mod(pk.N)
	p := l.ModMul(l, r, pk.N)
	return new(PlainText).SetModSymmetric(p, pk.N), nil
}

func (pk *PublicKey) NonceAdd(lhs, rhs *Nonce) (nonce *Nonce, err error) {
	if !pk.validNonce(lhs) {
		return nil, errs.NewValidation("invalid nonce")
	}
	if !pk.validNonce(rhs) {
		return nil, errs.NewValidation("invalid nonce")
	}

	return new(saferith.Nat).ModMul(lhs, rhs, pk.N), nil
}

func (pk *PublicKey) NonceSub(lhs, rhs *Nonce) (nonce *Nonce, err error) {
	if !pk.validNonce(lhs) {
		return nil, errs.NewValidation("invalid nonce")
	}
	if !pk.validNonce(rhs) {
		return nil, errs.NewValidation("invalid nonce")
	}

	rhsInv := new(saferith.Nat).ModInverse(rhs, pk.N)
	return new(saferith.Nat).ModMul(lhs, rhsInv, pk.N), nil
}

func (pk *PublicKey) NonceNeg(lhs *Nonce) (nonce *Nonce, err error) {
	if !pk.validNonce(lhs) {
		return nil, errs.NewValidation("invalid nonce")
	}

	return new(saferith.Nat).ModInverse(lhs, pk.N), nil
}

func (pk *PublicKey) NonceMul(lhs *Nonce, rhs *Scalar) (nonce *Nonce, err error) {
	if !pk.validNonce(lhs) {
		return nil, errs.NewValidation("invalid nonce")
	}
	if !pk.validScalar(rhs) {
		return nil, errs.NewValidation("invalid nonce")
	}

	rNeg := rhs.IsNegative()
	rAbs := rhs.Abs()
	lhsInv := new(saferith.Nat).ModInverse(lhs, pk.N)
	l := new(saferith.Nat)
	l.CondAssign(rNeg, lhsInv)
	l.CondAssign(rNeg^1, lhs)

	r, err := modular.FastExp(l, rAbs, pk.N)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to multiply nonce")
	}

	return r, nil
}

func (pk *PublicKey) CipherTextAdd(lhs, rhs *CipherText) (cipherText *CipherText, err error) {
	if !pk.validCiphertext(lhs) {
		return nil, errs.NewValidation("invalid ciphertext")
	}
	if !pk.validCiphertext(rhs) {
		return nil, errs.NewValidation("invalid ciphertext")
	}

	cipherText = new(CipherText)
	cipherText.C.ModMul(&lhs.C, &rhs.C, pk.nn)
	return cipherText, nil
}

func (pk *PublicKey) CipherTextAddPlainText(lhs *CipherText, rhs *PlainText) (cipherText *CipherText, err error) {
	if !pk.validCiphertext(lhs) {
		return nil, errs.NewValidation("invalid ciphertext")
	}
	if !pk.validPlaintext(rhs) {
		return nil, errs.NewValidation("invalid plaintext")
	}

	gToM := pk.gToM(rhs)
	cipherText = new(CipherText)
	cipherText.C.ModMul(&lhs.C, gToM, pk.nn)
	return cipherText, nil
}

func (pk *PublicKey) CipherTextSub(lhs, rhs *CipherText) (cipherText *CipherText, err error) {
	if !pk.validCiphertext(lhs) {
		return nil, errs.NewValidation("invalid ciphertext")
	}
	if !pk.validCiphertext(rhs) {
		return nil, errs.NewValidation("invalid ciphertext")
	}

	rhsInv := new(saferith.Nat).ModInverse(&rhs.C, pk.nn)
	cipherText = new(CipherText)
	cipherText.C.ModMul(&lhs.C, rhsInv, pk.nn)
	return cipherText, nil
}

func (pk *PublicKey) CipherTextSubPlainText(lhs *CipherText, rhs *PlainText) (cipherText *CipherText, err error) {
	if !pk.validCiphertext(lhs) {
		return nil, errs.NewValidation("invalid ciphertext")
	}
	if !pk.validPlaintext(rhs) {
		return nil, errs.NewValidation("invalid plaintext")
	}

	gToM := pk.gToM(rhs)
	gToMInv := new(saferith.Nat).ModInverse(gToM, pk.nn)
	cipherText = new(CipherText)
	cipherText.C.ModMul(&lhs.C, gToMInv, pk.nn)
	return cipherText, nil
}

func (pk *PublicKey) CipherTextNeg(lhs *CipherText) (cipherText *CipherText, err error) {
	if !pk.validCiphertext(lhs) {
		return nil, errs.NewValidation("invalid ciphertext")
	}

	cipherText = new(CipherText)
	cipherText.C.ModInverse(&lhs.C, pk.nn)
	return cipherText, nil
}

func (pk *PublicKey) CipherTextMul(lhs *CipherText, rhs *Scalar) (cipherText *CipherText, err error) {
	if !pk.validCiphertext(lhs) {
		return nil, errs.NewValidation("invalid ciphertext")
	}
	if !pk.validScalar(rhs) {
		return nil, errs.NewValidation("invalid scalar")
	}

	rNeg := rhs.IsNegative()
	rAbs := rhs.Abs()
	lhsInv := new(saferith.Nat).ModInverse(&lhs.C, pk.nn)
	l := new(saferith.Nat)
	l.CondAssign(rNeg, lhsInv)
	l.CondAssign(rNeg^1, &lhs.C)

	c, err := modular.FastExp(l, rAbs, pk.nn)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to multiply ciphertext")
	}

	cipherText = new(CipherText)
	cipherText.C.SetNat(c)
	return cipherText, nil
}

func (pk *PublicKey) validScalar(s *Scalar) bool {
	return pk.validPlaintext(s)
}
