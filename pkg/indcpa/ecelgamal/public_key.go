package ecelgamal

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa"
)

var (
	_ indcpa.HomomorphicEncryptionKey[PlainText, Nonce, *CipherText, Scalar] = (*PublicKey)(nil)
)

type PublicKey struct {
	G curves.Point
	H curves.Point

	_ ds.Incomparable
}

func (pk *PublicKey) RandomNonce(prng io.Reader) (nonce curves.Scalar, err error) {
	r, err := pk.H.Curve().ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample nonce")
	}
	return r, nil
}

func (pk *PublicKey) Encrypt(plainText PlainText, prng io.Reader) (*CipherText, Nonce, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil {
		return nil, nil, errs.NewValidation("invalid plainText")
	}
	nonce, err := pk.RandomNonce(prng)
	if err != nil {
		return nil, nil, errs.NewRandomSample("cannot sample nonce")
	}
	cipherText, err := pk.EncryptWithNonce(plainText, nonce)
	if err != nil {
		return nil, nil, errs.NewRandomSample("cannot encrypt with nonce")
	}
	return cipherText, nonce, nil
}

func (pk *PublicKey) EncryptWithNonce(plainText PlainText, nonce Nonce) (*CipherText, error) {
	if plainText == nil {
		return nil, errs.NewValidation("invalid plainText")
	}
	s := pk.H.ScalarMul(nonce)
	cipherText := &CipherText{
		C1: pk.G.ScalarMul(nonce),
		C2: s.Add(plainText),
	}
	return cipherText, nil
}

func (*PublicKey) PlainTextAdd(lhs, rhs PlainText) (PlainText, error) {
	if lhs == nil || rhs == nil {
		return nil, errs.NewValidation("invalid plainText")
	}
	plainText := lhs.Add(rhs)
	return plainText, nil
}

func (*PublicKey) PlainTextSub(lhs, rhs PlainText) (PlainText, error) {
	if lhs == nil || rhs == nil {
		return nil, errs.NewValidation("invalid plainText")
	}
	return lhs.Sub(rhs), nil
}

func (*PublicKey) PlainTextNeg(plainText PlainText) (PlainText, error) {
	if plainText == nil {
		return nil, errs.NewValidation("invalid plainText")
	}
	return plainText.Neg(), nil
}

func (*PublicKey) PlainTextMul(plainText PlainText, scalar Scalar) (PlainText, error) {
	if plainText == nil || scalar == nil {
		return nil, errs.NewValidation("invalid plainText")
	}
	return plainText.ScalarMul(scalar), nil
}

func (*PublicKey) NonceAdd(lhs, rhs Nonce) (Nonce, error) {
	if lhs == nil || rhs == nil {
		return nil, errs.NewIsNil("argument")
	}
	return lhs.Add(rhs), nil
}

func (*PublicKey) NonceSub(lhs, rhs Nonce) (Nonce, error) {
	if lhs == nil || rhs == nil {
		return nil, errs.NewIsNil("argument")
	}
	return lhs.Sub(rhs), nil
}

func (*PublicKey) NonceNeg(nonce Nonce) (Nonce, error) {
	if nonce == nil {
		return nil, errs.NewIsNil("argument")
	}
	return nonce.Neg(), nil
}

func (*PublicKey) NonceMul(nonce Nonce, s Scalar) (Nonce, error) {
	if nonce == nil || s == nil {
		return nil, errs.NewIsNil("argument")
	}
	return nonce.Mul(s), nil
}

func (*PublicKey) CipherTextAdd(lhs, rhs *CipherText) (*CipherText, error) {
	if lhs == nil || rhs == nil {
		return nil, errs.NewIsNil("argument")
	}
	cipherText := &CipherText{
		C1: lhs.C1.Add(rhs.C1),
		C2: lhs.C2.Add(rhs.C2),
	}
	return cipherText, nil
}

func (*PublicKey) CipherTextAddPlainText(cipherText *CipherText, plainText PlainText) (*CipherText, error) {
	if cipherText == nil || plainText == nil {
		return nil, errs.NewIsNil("argument")
	}
	newCipherText := &CipherText{
		C1: cipherText.C1,
		C2: cipherText.C2.Add(plainText),
	}
	return newCipherText, nil
}

func (*PublicKey) CipherTextSub(lhs, rhs *CipherText) (*CipherText, error) {
	if lhs == nil || rhs == nil {
		return nil, errs.NewIsNil("argument")
	}
	cipherText := &CipherText{
		C1: lhs.C1.Sub(rhs.C1),
		C2: lhs.C2.Sub(rhs.C2),
	}
	return cipherText, nil
}

func (*PublicKey) CipherTextSubPlainText(cipherText *CipherText, plainText PlainText) (*CipherText, error) {
	if cipherText == nil || plainText == nil {
		return nil, errs.NewIsNil("argument")
	}
	newCipherText := &CipherText{
		C1: cipherText.C1,
		C2: cipherText.C2.Sub(plainText),
	}
	return newCipherText, nil
}

func (*PublicKey) CipherTextNeg(lhs *CipherText) (*CipherText, error) {
	if lhs == nil {
		return nil, errs.NewIsNil("argument")
	}
	cipherText := &CipherText{
		C1: lhs.C1.Neg(),
		C2: lhs.C2.Neg(),
	}
	return cipherText, nil
}

func (*PublicKey) CipherTextMul(lhs *CipherText, s Scalar) (*CipherText, error) {
	if lhs == nil || s == nil {
		return nil, errs.NewIsNil("argument")
	}
	cipherText := &CipherText{
		C1: lhs.C1.ScalarMul(s),
		C2: lhs.C2.ScalarMul(s),
	}
	return cipherText, nil
}

func (*PublicKey) CipherTextEqual(lhs, rhs *CipherText) bool {
	if rhs == nil || lhs == nil {
		return rhs == lhs
	}
	return lhs.C1.Equal(rhs.C1) && lhs.C2.Equal(rhs.C2)
}
